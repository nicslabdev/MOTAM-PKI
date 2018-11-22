/***************************************************************************************/
/*
 * motam_ca
 * Created by Manuel Montenegro, Nov 22, 2018.
 * Developed for MOTAM project.
 *
 *  This application supports the CA of the MOTAM beacons platform. Generates the
 *  certificates (aka mini-certs) with information such beacons public key, beacons ID,
 *  start date and validity time.
 *
 *  This code has been developed for Nordic Semiconductor nRF52840 PDK & nRF52840 dongle.
*/
/***************************************************************************************/

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "nrf.h"
#include "nrf_pwr_mgmt.h"
#include "nrf_drv_usbd.h"
#include "nrf_drv_clock.h"
#include "nrf_gpio.h"
#include "nrf_delay.h"
#include "nrf_drv_power.h"

#include "app_error.h"
#include "app_util.h"
#include "app_usbd_core.h"
#include "app_usbd.h"
#include "app_usbd_string_desc.h"
#include "app_usbd_cdc_acm.h"
#include "app_usbd_serial_num.h"

#include "boards.h"
#include "bsp.h"
#include "bsp_cli.h"
#include "nrf_cli.h"
#include "nrf_cli_uart.h"

#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"

#include "sdk_common.h"
#include "nrf_assert.h"

#include "mem_manager.h"
#include "nrf_crypto.h"
#include "nrf_crypto_ecc.h"
#include "nrf_crypto_hash.h"
#include "nrf_crypto_error.h"


// ======== Cryptographic configuration ========

#define MINI_CERT_SIZE					137									// Mini certificate size in bytes
#define PUB_KEY_SIZE					64									// ECC Secp256k1 public key size
#define PRIV_KEY_SIZE					32									// ECC Secp256k1 private key size

static uint8_t beaconMiniCert [MINI_CERT_SIZE];								// Generated mini certificate of beacon

static const uint8_t caPrivateKeyRaw[] =									// CA private key on raw format
{
		0xF8, 0x54, 0xD7, 0x62, 0x6E, 0x8C, 0x67, 0xC0,
		0x5E, 0xE1, 0xFE, 0x23, 0x33, 0xEB, 0x9E, 0xD0,
		0xF1, 0x4D, 0x10, 0x50, 0x05, 0x86, 0xEB, 0x2C,
		0x0F, 0x2F, 0x9D, 0xAD, 0xDE, 0x93, 0xCC, 0x13
};

static const uint8_t caPublicKeyRaw[] =										// CA public key on raw format
{
		0x6D, 0xF8, 0xF5, 0x72, 0x97, 0x47, 0x27, 0x22,
		0x0D, 0x38, 0xD7, 0xFA, 0x77, 0x92, 0x21, 0xCA,
		0xBE, 0x41, 0xFB, 0x93, 0x60, 0x9D, 0x65, 0x38,
		0xB2, 0xBF, 0xE4, 0x83, 0x3E, 0x2B, 0x1B, 0x8E,
		0x0E, 0xE2, 0x07, 0xC0, 0x90, 0xA9, 0x74, 0x8F,
		0xB9, 0x32, 0x08, 0x48, 0x9E, 0xF7, 0xD6, 0x73,
		0x87, 0x5A, 0xB9, 0x52, 0x0B, 0x99, 0xD5, 0x2F,
		0x35, 0xEA, 0x49, 0x17, 0x87, 0xFE, 0x96, 0xFC
};

static nrf_crypto_ecc_private_key_t 		caPrivateKey;					// CA private key on internal representation
static nrf_crypto_ecc_public_key_t 			caPublicKey;					// CA public key on internal representation

// Cryptographic module initialization
static void crypto_init()
{
	ret_code_t err_code;

	err_code = nrf_mem_init();
	APP_ERROR_CHECK(err_code);

	err_code = nrf_crypto_init();
    APP_ERROR_CHECK(err_code);
}

// CA keys generation: public key from static private key and conversion to internal representation
static void ca_keys_generation (void)
{
	ret_code_t err_code;

    // Converts private key in raw format to internal representation
    err_code = nrf_crypto_ecc_private_key_from_raw	(
    												&g_nrf_crypto_ecc_secp256k1_curve_info,
													&caPrivateKey,
													caPrivateKeyRaw,
													sizeof(caPrivateKeyRaw)
													);
    APP_ERROR_CHECK(err_code);

    // Converts public key in raw format to internal representation
	err_code = nrf_crypto_ecc_public_key_from_raw	(
													&g_nrf_crypto_ecc_secp256k1_curve_info,
													&caPublicKey,
													caPublicKeyRaw,
													sizeof(caPublicKeyRaw)
													);
	APP_ERROR_CHECK(err_code);
}

/*
 * Generate mini-certificate for a new MOTAM beacon signed by CA private key
 * 	[out] uint8_t*	miniCert:		Pointer to generated mini-cert (137 bytes)
 *  [in] uint8_t*	beaconPubKey:	Pointer to beacon public key byte array
 * 	[in] uint8_t 	beaconId: 		MOTAM beacon identifier (assigned by user)
 * 	[in] uint32_t 	valNotBefor: 	Start date of validity period in UNIX timestamp representation
 * 	[in] uint32_t 	valNotAfter: 	End date of validity period in UNIX timestamp representation
 */
static void generate_mini_cert (uint8_t * miniCert, uint8_t* beaconPubKey, uint8_t beaconId, uint32_t valNotBefore, uint32_t valNotAfter)
{
	ret_code_t err_code;

	size_t certDataLen = 73;												// Size in bytes of mini-cert data
	nrf_crypto_hash_sha256_digest_t hashDigest;								// Hash digest
	size_t hashDigestLen;													// Hash digest length
	nrf_crypto_hash_context_t hashContext;									// Structure holding context information for the hash calculation
	nrf_crypto_ecdsa_secp256k1_signature_t dataSignature;					// ECDSA Secp256k1 signature
	size_t dataSignatureSize=NRF_CRYPTO_ECDSA_SECP256K1_SIGNATURE_SIZE;		// ECDSA Secp256k1 signature size

	// Copy data included in mini certificate
	memset (miniCert, 0, MINI_CERT_SIZE);
	memcpy (&miniCert[0], 	beaconPubKey, 	PUB_KEY_SIZE);
	memcpy (&miniCert[1], 	&beaconId, 		sizeof(beaconId));
	memcpy (&miniCert[65], 	&valNotBefore, 	sizeof(valNotBefore));
	memcpy (&miniCert[69], 	&valNotAfter, 	sizeof(valNotAfter));

	// Generate ecdsa signature of the mini-cert data
	err_code = nrf_crypto_hash_calculate	(								// SHA-256 hash of mini-cert data
											&hashContext,					// Bug in this SDK. Setting NULL pointer won't work.
	                                   		&g_nrf_crypto_hash_sha256_info,
											miniCert,
											certDataLen,
											hashDigest,
											&hashDigestLen
											);
	APP_ERROR_CHECK(err_code);

	err_code = nrf_crypto_ecdsa_sign	(									// ECDSA signature of mini-cert data
										NULL,
										&caPrivateKey,
										hashDigest,
										hashDigestLen,
										dataSignature,
										&dataSignatureSize
										);
	APP_ERROR_CHECK(err_code);

	NRF_LOG_RAW_INFO("Calculated signature of data:\r\nSize:%d\r\n", dataSignatureSize);
	NRF_LOG_RAW_HEXDUMP_INFO(dataSignature, dataSignatureSize);

	// Include the data signature to mini-cert buffer
	memcpy (&miniCert[73], &dataSignature, dataSignatureSize);
}


// ======== USB Device CDC ACM configuration ========

// Enable power USB detection
#ifndef USBD_POWER_DETECTION
#define USBD_POWER_DETECTION true
#endif

// USB Device CDC ACM board configuration parameters
#define CDC_ACM_COMM_INTERFACE  0
#define CDC_ACM_COMM_EPIN       NRF_DRV_USBD_EPIN2
#define CDC_ACM_DATA_INTERFACE  1
#define CDC_ACM_DATA_EPIN       NRF_DRV_USBD_EPIN1
#define CDC_ACM_DATA_EPOUT      NRF_DRV_USBD_EPOUT1
#define WRITE_BUFFER_SIZE		1024										// Size of CDC ACM write buffer
#define READ_BUFFER_SIZE		5											// Size of CDC ACM read buffer

// USB Device CDC ACM user event handler
static void cdc_acm_user_ev_handler(app_usbd_class_inst_t const * p_inst, app_usbd_cdc_acm_user_event_t event);

// Function that check if data received by USB CDC ACM is a valid command (function declaration)
static void check_command (app_usbd_cdc_acm_t const * p_cdc_acm);

// USB Device CDC ACM instance
APP_USBD_CDC_ACM_GLOBAL_DEF(m_app_cdc_acm,
                            cdc_acm_user_ev_handler,
                            CDC_ACM_COMM_INTERFACE,
                            CDC_ACM_DATA_INTERFACE,
                            CDC_ACM_COMM_EPIN,
                            CDC_ACM_DATA_EPIN,
                            CDC_ACM_DATA_EPOUT,
                            APP_USBD_CDC_COMM_PROTOCOL_AT_V250
);

// USB Device CDC ACM transmission buffers
static char m_tx_buffer[WRITE_BUFFER_SIZE];
static char rx_buffer [READ_BUFFER_SIZE];

// USB CDC ACM Commands
static char show_cmd [] = {'s','h','o','w','\r'};							// Show mini-cert



// USB Device CDC ACM user event handler
static void cdc_acm_user_ev_handler(app_usbd_class_inst_t const * p_inst, app_usbd_cdc_acm_user_event_t event)
{

	ret_code_t err_code;

	// Get cdc_acm from base class instance.
	app_usbd_cdc_acm_t const * p_cdc_acm = app_usbd_cdc_acm_class_get(p_inst);

    switch (event)
    {
        case APP_USBD_CDC_ACM_USER_EVT_PORT_OPEN:
        	// Setup first transfer
//        	NRF_LOG_INFO("first transfer!!!!!!!!");
			err_code = app_usbd_cdc_acm_read(
											&m_app_cdc_acm,
											rx_buffer,
											READ_BUFFER_SIZE
											);
			UNUSED_VARIABLE(err_code);										// Just ignore err_code
        	break;
        case APP_USBD_CDC_ACM_USER_EVT_PORT_CLOSE:
            break;
        case APP_USBD_CDC_ACM_USER_EVT_TX_DONE:
            break;
        case APP_USBD_CDC_ACM_USER_EVT_RX_DONE:
			check_command(p_cdc_acm);
			break;
        default:
            break;
    }
}

// USB Device event handler
static void usbd_user_ev_handler(app_usbd_event_type_t event)
{
    switch (event)
    {
        case APP_USBD_EVT_DRV_SUSPEND:
            break;
        case APP_USBD_EVT_DRV_RESUME:
            break;
        case APP_USBD_EVT_STARTED:
            break;
        case APP_USBD_EVT_STOPPED:
            app_usbd_disable();
            break;
        case APP_USBD_EVT_POWER_DETECTED:
            if (!nrf_drv_usbd_is_enabled())
            {
                app_usbd_enable();
            }
            break;
        case APP_USBD_EVT_POWER_REMOVED:
            app_usbd_stop();
            break;
        case APP_USBD_EVT_POWER_READY:
            app_usbd_start();
            break;
        default:
            break;
    }
}

// USB Device initialization
static void usbd_init (void)
{
	ret_code_t err_code;

	app_usbd_serial_num_generate();

	static const app_usbd_config_t usbd_config = {
		.ev_state_proc = usbd_user_ev_handler
	};

	err_code = app_usbd_init(&usbd_config);
	APP_ERROR_CHECK(err_code);

	app_usbd_class_inst_t const * class_cdc_acm = app_usbd_cdc_acm_class_inst_get(&m_app_cdc_acm);
	err_code = app_usbd_class_append(class_cdc_acm);
	APP_ERROR_CHECK(err_code);
}

// Function that enables USB Device events. This function must be called after BLE functions starts (if exists)
static void usbd_start (void)
{
	ret_code_t err_code;
	err_code = app_usbd_power_events_enable();
	APP_ERROR_CHECK(err_code);
}

// Function that check if data received by USB CDC ACM is a valid command
static void check_command (app_usbd_cdc_acm_t const * p_cdc_acm)
{
	ret_code_t err_code;

	NRF_LOG_INFO("Bytes waiting: %d", app_usbd_cdc_acm_bytes_stored(p_cdc_acm));
	do
	{
		NRF_LOG_INFO("RECIBIDO!");
		/*Get amount of data transfered*/
		size_t size = app_usbd_cdc_acm_rx_size(p_cdc_acm);
		NRF_LOG_INFO("RX: size: %lu char: %c%c%c%c%c", size, rx_buffer[0], rx_buffer[1], rx_buffer[2], rx_buffer[3], rx_buffer[4] );
		/* Fetch data until internal buffer is empty */
		err_code = app_usbd_cdc_acm_read(&m_app_cdc_acm,
									rx_buffer,
									READ_BUFFER_SIZE);
		NRF_LOG_INFO("err_code: %d", err_code);
	} while (err_code == NRF_SUCCESS);

	if (memcmp (rx_buffer, show_cmd, READ_BUFFER_SIZE) == 0)
	{
		// Conversion from byte string to hexadecimal char string
		int i;
		for (i = 0; i < sizeof(beaconMiniCert); i++ )
		{
			sprintf(&m_tx_buffer[i*2], "%02x", beaconMiniCert[i]);
		}
		NRF_LOG_INFO("INDEX: %d", i);
		sprintf(&m_tx_buffer[(i*2)], "\r\n");

		// Send the hexadecimal char string by serial port
		app_usbd_cdc_acm_write(&m_app_cdc_acm, m_tx_buffer, (sizeof(beaconMiniCert)*2)+2);
	}
	else
	{
		char unk_comm [] = "UNKNOWN COMMAND. Try \"show\"\r\n";
		memcpy(m_tx_buffer, unk_comm, sizeof(unk_comm));
		// Send the hexadecimal char string by serial port
		app_usbd_cdc_acm_write(&m_app_cdc_acm, unk_comm, sizeof(unk_comm));
	}
}


// ======== Board Initialization ========

// Logging initialization
static void log_init(void)
{
    ret_code_t err_code = NRF_LOG_INIT(NULL);
    APP_ERROR_CHECK(err_code);

    NRF_LOG_DEFAULT_BACKENDS_INIT();
}

// Clock initialization
static void clock_init (void)
{
	ret_code_t err_code = nrf_drv_clock_init();
    APP_ERROR_CHECK(err_code);

    nrf_drv_clock_lfclk_request(NULL);

    while(!nrf_drv_clock_lfclk_is_running())
    {
        /* Just waiting */
    }
}

// Timer initialization
static void timer_init(void)
{
    ret_code_t err_code = app_timer_init();
    APP_ERROR_CHECK(err_code);
}

// Power managemente initialization
static void power_management_init(void)
{
    ret_code_t err_code;
    err_code = nrf_pwr_mgmt_init();
    APP_ERROR_CHECK(err_code);
}

// Function for handling the idle state (main loop)
static void idle_state_handle(void)
{
    if (NRF_LOG_PROCESS() == false)
    {
        nrf_pwr_mgmt_run();
    }
}


int main(void)
{

	// Initialization
	log_init();
	timer_init();
	clock_init();
	power_management_init();
	crypto_init();

	// USBD CDC ACM initialization and start
	usbd_init();
	usbd_start();

	// Keys Generation
	ca_keys_generation ();

	// Testing mini certificate generation
	uint8_t beaconPublicKey [] =
	{
			0xF4, 0x8B, 0x3F, 0x29, 0x35, 0xC1, 0x83, 0x81,
			0x13, 0x7E, 0x42, 0x6C, 0x01, 0x18, 0xBA, 0x6C,
			0x20, 0xE9, 0x17, 0x6C, 0xCE, 0xE2, 0x0B, 0xBF,
			0x90, 0x00, 0x1E, 0x6B, 0x90, 0x66, 0x46, 0xD0,
			0x29, 0x3C, 0xCB, 0x85, 0xBD, 0x27, 0x38, 0xAD,
			0x46, 0x9E, 0xAB, 0xAA, 0x91, 0x45, 0xEF, 0xF4,
			0x86, 0xF6, 0x9C, 0x25, 0xFE, 0x4A, 0x04, 0xA4,
			0x3E, 0x04, 0x14, 0x37, 0x7E, 0xE6, 0x68, 0x73
	};

	uint8_t beaconId = 0;

	generate_mini_cert (beaconMiniCert, beaconPublicKey, beaconId, 1542270683, 1573810370);
	NRF_LOG_RAW_INFO("Beacon mini-cert:\r\nSize: %d\r\n", sizeof(beaconMiniCert));
	NRF_LOG_RAW_HEXDUMP_INFO(beaconMiniCert, sizeof(beaconMiniCert));

	for (;;)
	{

		while (app_usbd_event_queue_process())
		{
			// While there are USBD events in queue...
		}
		idle_state_handle();
	}
}
