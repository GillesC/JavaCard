package be.msec.smartcard;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.CardException;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.PrivateKey;
import javacard.security.PublicKey;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public class IdentityCard extends Applet {
	private final static byte IDENTITY_CARD_CLA = (byte) 0x80;

	private static final byte VALIDATE_PIN_INS = 0x22;
	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	private final static short SW_TEST = 0x6302;
	
	private static final short MW_MUST_BE_AUTHENTICATED = 0x63ff;
    private static final short CHALLENGE_NOT_ACCEPTED = 0x63fe;
    private static final short NO_SHOP_FOUND = 0x63fd;

	private static final byte GET_SERIAL_INS = 0x24;
	private static final byte GET_NAME_INS = 0x26;
	private static final byte CHALLENGE_INS = 0x28;
	private static final byte GET_CERTIFICATE_INS = 0x30;
	private static final byte GET_CERTIFICATE_SIZE_INS = 0x32;

	// Practicum instructies
	private static final byte GET_EC_CERTIFICATE = 0x34;
	private static final byte CLEAR_OFFSET_INS = 0x35;

	private static final byte GENERATE_SESSION_KEY = 0x36;

	private final static byte PIN_TRY_LIMIT = (byte) 0x03;
	private final static byte PIN_SIZE = (byte) 0x04;
	
	
	//private static final byte SET = 0x37;
    //private static final byte PULL = 0x38;
	
	private static final byte ENCRYPT_BYTES_WITH_SESSION_KEY = 0x37;
	//private static final byte DECRYPT_BYTES_WITH_SESSION_KEY = 0x39;
	
	
	
    private static final byte REGISTER_SHOP_PSEUDONYM = 0x38;
    private static final byte REGISTER_SHOP_CERTIFICATE = 0x39;
    private static final byte REGISTER_SHOP_NAME = 0x40;
    private static final byte REGISTER_SHOP_COMPLETE = 0x41;
    
    
    private static final byte CLOSE_SECURE_CONNECTION = 0x42;
    
    private static final byte INIT_CHALLENGE = 0x44;
    private static final byte CHALLENGE_ACCEPTED = 0x45;
    private static final byte GET_NEXT_CHALLENGE = 0x46;
    public static final byte GET_CURRENT_CHALLENGE = 0x47;
    
    public static final byte REGISTER_SHOP_CERTIFICATE_PART1 = 0x48;
    public static final byte REGISTER_SHOP_CERTIFICATE_PART2 = 0x49;
    public static final byte REGISTER_SHOP_CERTIFICATE_PART3 = 0x50;

    public static final byte GET_PSEUDONYM_CERTIFICATE_PART1 = 0x51;
    public static final byte GET_PSEUDONYM_CERTIFICATE_PART2 = 0x52;
    public static final byte GET_PSEUDONYM_CERTIFICATE_PART3 = 0x53;


    public static final byte SELECT_SHOP = 0x54;
    private byte[] selectedShopEntry;
    public static final byte CHANGE_LP = 0x55;
    
    public static final byte GET_NUMBER_OF_LOGS = 0x56;
    public static final byte GET_NEXT_LOG = 0x57;
    public static final byte CLEAR_LOGS= 0x58;   
    
    
    public static final byte GET_LP = 0x59;
    
    
    
    
    
    private static final byte TEST = 0x43;
    

	private static final short numBytesToRead = 0;
	
	private static final short certificateLen = 413;
	private static final short pseudonymLen = 26;



	byte[] privExponent = new byte[]{(byte) 0x64, (byte) 0xc2, (byte) 0x8d, (byte) 0xcf, (byte) 0xa1, (byte) 0x1a, (byte) 0x7e, (byte) 0x6a, (byte) 0xc9, (byte) 0x42, (byte) 0xf7, (byte) 0xb6, (byte) 0xad, (byte) 0x86, (byte) 0xdb, (byte) 0xf5, (byte) 0x20, (byte) 0x7c, (byte) 0xcd, (byte) 0x4d, (byte) 0xe9, (byte) 0xfb, (byte) 0x2e, (byte) 0x2b, (byte) 0x99, (byte) 0xfa, (byte) 0x29, (byte) 0x1e, (byte) 0xd9, (byte) 0xbd, (byte) 0xf9, (byte) 0xb2, (byte) 0x77, (byte) 0x9e, (byte) 0x3e, (byte) 0x1a, (byte) 0x60, (byte) 0x67, (byte) 0x8e, (byte) 0xbd, (byte) 0xae, (byte) 0x36, (byte) 0x54, (byte) 0x4a, (byte) 0x11, (byte) 0xc2, (byte) 0x2e, (byte) 0x7c, (byte) 0x9e, (byte) 0xc3, (byte) 0xcb, (byte) 0xba, (byte) 0x65, (byte) 0x2b, (byte) 0xc5, (byte) 0x1b, (byte) 0x6f, (byte) 0x4f, (byte) 0x54, (byte) 0xe1, (byte) 0xff, (byte) 0xc3, (byte) 0x18, (byte) 0x81};


	byte[] privModulus = new byte[]{(byte) 0x8d, (byte) 0x08, (byte) 0x00, (byte) 0x7e, (byte) 0x39, (byte) 0xb1, (byte) 0x52, (byte) 0x4e, (byte) 0xc8, (byte) 0x90, (byte) 0x90, (byte) 0x37, (byte) 0x93, (byte) 0xd1, (byte) 0xcc, (byte) 0x33, (byte) 0xa8, (byte) 0x8d, (byte) 0xd5, (byte) 0x88, (byte) 0x7d, (byte) 0x5c, (byte) 0xcc, (byte) 0x8a, (byte) 0x26, (byte) 0xaa, (byte) 0x05, (byte) 0x2d, (byte) 0x7c, (byte) 0xed, (byte) 0xd9, (byte) 0xc4, (byte) 0xec, (byte) 0x89, (byte) 0x4e, (byte) 0x27, (byte) 0x85, (byte) 0x9b, (byte) 0x33, (byte) 0x43, (byte) 0x72, (byte) 0xae, (byte) 0xe2, (byte) 0xc8, (byte) 0x4d, (byte) 0x7c, (byte) 0x04, (byte) 0x02, (byte) 0xcd, (byte) 0x46, (byte) 0xf0, (byte) 0x3b, (byte) 0xd8, (byte) 0xa0, (byte) 0xb9, (byte) 0xd1, (byte) 0x9d, (byte) 0x33, (byte) 0x44, (byte) 0xe1, (byte) 0xfa, (byte) 0x0d, (byte) 0xf6, (byte) 0x69};


	byte[] pubExponent = new byte[]{(byte) 0x01, (byte) 0x00, (byte) 0x01};


	byte[] pubModulus = new byte[]{(byte) 0x8d, (byte) 0x08, (byte) 0x00, (byte) 0x7e, (byte) 0x39, (byte) 0xb1, (byte) 0x52, (byte) 0x4e, (byte) 0xc8, (byte) 0x90, (byte) 0x90, (byte) 0x37, (byte) 0x93, (byte) 0xd1, (byte) 0xcc, (byte) 0x33, (byte) 0xa8, (byte) 0x8d, (byte) 0xd5, (byte) 0x88, (byte) 0x7d, (byte) 0x5c, (byte) 0xcc, (byte) 0x8a, (byte) 0x26, (byte) 0xaa, (byte) 0x05, (byte) 0x2d, (byte) 0x7c, (byte) 0xed, (byte) 0xd9, (byte) 0xc4, (byte) 0xec, (byte) 0x89, (byte) 0x4e, (byte) 0x27, (byte) 0x85, (byte) 0x9b, (byte) 0x33, (byte) 0x43, (byte) 0x72, (byte) 0xae, (byte) 0xe2, (byte) 0xc8, (byte) 0x4d, (byte) 0x7c, (byte) 0x04, (byte) 0x02, (byte) 0xcd, (byte) 0x46, (byte) 0xf0, (byte) 0x3b, (byte) 0xd8, (byte) 0xa0, (byte) 0xb9, (byte) 0xd1, (byte) 0x9d, (byte) 0x33, (byte) 0x44, (byte) 0xe1, (byte) 0xfa, (byte) 0x0d, (byte) 0xf6, (byte) 0x69};


	byte[] pubKeySC = new byte[]{(byte) 0x30, (byte) 0x5c, (byte) 0x30, (byte) 0x0d, (byte) 0x06, (byte) 0x09, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0x86, (byte) 0xf7, (byte) 0x0d, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x05, (byte) 0x00, (byte) 0x03, (byte) 0x4b, (byte) 0x00, (byte) 0x30, (byte) 0x48, (byte) 0x02, (byte) 0x41, (byte) 0x00, (byte) 0x8d, (byte) 0x08, (byte) 0x00, (byte) 0x7e, (byte) 0x39, (byte) 0xb1, (byte) 0x52, (byte) 0x4e, (byte) 0xc8, (byte) 0x90, (byte) 0x90, (byte) 0x37, (byte) 0x93, (byte) 0xd1, (byte) 0xcc, (byte) 0x33, (byte) 0xa8, (byte) 0x8d, (byte) 0xd5, (byte) 0x88, (byte) 0x7d, (byte) 0x5c, (byte) 0xcc, (byte) 0x8a, (byte) 0x26, (byte) 0xaa, (byte) 0x05, (byte) 0x2d, (byte) 0x7c, (byte) 0xed, (byte) 0xd9, (byte) 0xc4, (byte) 0xec, (byte) 0x89, (byte) 0x4e, (byte) 0x27, (byte) 0x85, (byte) 0x9b, (byte) 0x33, (byte) 0x43, (byte) 0x72, (byte) 0xae, (byte) 0xe2, (byte) 0xc8, (byte) 0x4d, (byte) 0x7c, (byte) 0x04, (byte) 0x02, (byte) 0xcd, (byte) 0x46, (byte) 0xf0, (byte) 0x3b, (byte) 0xd8, (byte) 0xa0, (byte) 0xb9, (byte) 0xd1, (byte) 0x9d, (byte) 0x33, (byte) 0x44, (byte) 0xe1, (byte) 0xfa, (byte) 0x0d, (byte) 0xf6, (byte) 0x69, (byte) 0x02, (byte) 0x03, (byte) 0x01, (byte) 0x00, (byte) 0x01};


	byte[] privKeySC = new byte[]{(byte) 0x30, (byte) 0x82, (byte) 0x01, (byte) 0x54, (byte) 0x02, (byte) 0x01, (byte) 0x00, (byte) 0x30, (byte) 0x0d, (byte) 0x06, (byte) 0x09, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0x86, (byte) 0xf7, (byte) 0x0d, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x05, (byte) 0x00, (byte) 0x04, (byte) 0x82, (byte) 0x01, (byte) 0x3e, (byte) 0x30, (byte) 0x82, (byte) 0x01, (byte) 0x3a, (byte) 0x02, (byte) 0x01, (byte) 0x00, (byte) 0x02, (byte) 0x41, (byte) 0x00, (byte) 0x8d, (byte) 0x08, (byte) 0x00, (byte) 0x7e, (byte) 0x39, (byte) 0xb1, (byte) 0x52, (byte) 0x4e, (byte) 0xc8, (byte) 0x90, (byte) 0x90, (byte) 0x37, (byte) 0x93, (byte) 0xd1, (byte) 0xcc, (byte) 0x33, (byte) 0xa8, (byte) 0x8d, (byte) 0xd5, (byte) 0x88, (byte) 0x7d, (byte) 0x5c, (byte) 0xcc, (byte) 0x8a, (byte) 0x26, (byte) 0xaa, (byte) 0x05, (byte) 0x2d, (byte) 0x7c, (byte) 0xed, (byte) 0xd9, (byte) 0xc4, (byte) 0xec, (byte) 0x89, (byte) 0x4e, (byte) 0x27, (byte) 0x85, (byte) 0x9b, (byte) 0x33, (byte) 0x43, (byte) 0x72, (byte) 0xae, (byte) 0xe2, (byte) 0xc8, (byte) 0x4d, (byte) 0x7c, (byte) 0x04, (byte) 0x02, (byte) 0xcd, (byte) 0x46, (byte) 0xf0, (byte) 0x3b, (byte) 0xd8, (byte) 0xa0, (byte) 0xb9, (byte) 0xd1, (byte) 0x9d, (byte) 0x33, (byte) 0x44, (byte) 0xe1, (byte) 0xfa, (byte) 0x0d, (byte) 0xf6, (byte) 0x69, (byte) 0x02, (byte) 0x03, (byte) 0x01, (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x40, (byte) 0x64, (byte) 0xc2, (byte) 0x8d, (byte) 0xcf, (byte) 0xa1, (byte) 0x1a, (byte) 0x7e, (byte) 0x6a, (byte) 0xc9, (byte) 0x42, (byte) 0xf7, (byte) 0xb6, (byte) 0xad, (byte) 0x86, (byte) 0xdb, (byte) 0xf5, (byte) 0x20, (byte) 0x7c, (byte) 0xcd, (byte) 0x4d, (byte) 0xe9, (byte) 0xfb, (byte) 0x2e, (byte) 0x2b, (byte) 0x99, (byte) 0xfa, (byte) 0x29, (byte) 0x1e, (byte) 0xd9, (byte) 0xbd, (byte) 0xf9, (byte) 0xb2, (byte) 0x77, (byte) 0x9e, (byte) 0x3e, (byte) 0x1a, (byte) 0x60, (byte) 0x67, (byte) 0x8e, (byte) 0xbd, (byte) 0xae, (byte) 0x36, (byte) 0x54, (byte) 0x4a, (byte) 0x11, (byte) 0xc2, (byte) 0x2e, (byte) 0x7c, (byte) 0x9e, (byte) 0xc3, (byte) 0xcb, (byte) 0xba, (byte) 0x65, (byte) 0x2b, (byte) 0xc5, (byte) 0x1b, (byte) 0x6f, (byte) 0x4f, (byte) 0x54, (byte) 0xe1, (byte) 0xff, (byte) 0xc3, (byte) 0x18, (byte) 0x81, (byte) 0x02, (byte) 0x21, (byte) 0x00, (byte) 0xc0, (byte) 0xd7, (byte) 0x59, (byte) 0x9d, (byte) 0xc7, (byte) 0x99, (byte) 0x76, (byte) 0x9f, (byte) 0x71, (byte) 0xb0, (byte) 0xd2, (byte) 0x73, (byte) 0xd9, (byte) 0x8f, (byte) 0x47, (byte) 0x3b, (byte) 0xe5, (byte) 0xd3, (byte) 0x5b, (byte) 0x97, (byte) 0x14, (byte) 0x41, (byte) 0x40, (byte) 0xf3, (byte) 0x65, (byte) 0x93, (byte) 0x53, (byte) 0x51, (byte) 0x80, (byte) 0xd6, (byte) 0xe6, (byte) 0x19, (byte) 0x02, (byte) 0x21, (byte) 0x00, (byte) 0xbb, (byte) 0x38, (byte) 0xad, (byte) 0xcd, (byte) 0x8d, (byte) 0x34, (byte) 0x84, (byte) 0x6c, (byte) 0x6d, (byte) 0x93, (byte) 0x2d, (byte) 0xca, (byte) 0xa1, (byte) 0x61, (byte) 0x1c, (byte) 0x11, (byte) 0xc0, (byte) 0x5c, (byte) 0xdf, (byte) 0x30, (byte) 0xc8, (byte) 0x40, (byte) 0xfe, (byte) 0xce, (byte) 0xa7, (byte) 0xa0, (byte) 0x2e, (byte) 0xe1, (byte) 0x21, (byte) 0x68, (byte) 0x7c, (byte) 0xd1, (byte) 0x02, (byte) 0x21, (byte) 0x00, (byte) 0xb4, (byte) 0x06, (byte) 0x16, (byte) 0x1e, (byte) 0x2a, (byte) 0x60, (byte) 0xc4, (byte) 0x91, (byte) 0xb2, (byte) 0xb4, (byte) 0x0c, (byte) 0xb3, (byte) 0xa4, (byte) 0x0d, (byte) 0x92, (byte) 0xc5, (byte) 0x83, (byte) 0x17, (byte) 0x1d, (byte) 0xf0, (byte) 0xdb, (byte) 0x32, (byte) 0xd3, (byte) 0xac, (byte) 0xa5, (byte) 0x4d, (byte) 0xb4, (byte) 0xc1, (byte) 0x68, (byte) 0x92, (byte) 0xb5, (byte) 0xb9, (byte) 0x02, (byte) 0x20, (byte) 0x0c, (byte) 0x9f, (byte) 0xb6, (byte) 0xc0, (byte) 0x6c, (byte) 0x6c, (byte) 0x05, (byte) 0x1d, (byte) 0xd6, (byte) 0x89, (byte) 0x9d, (byte) 0x05, (byte) 0xd3, (byte) 0xb9, (byte) 0xdb, (byte) 0x8d, (byte) 0xaa, (byte) 0xdd, (byte) 0xd8, (byte) 0x42, (byte) 0xce, (byte) 0xcd, (byte) 0xeb, (byte) 0x20, (byte) 0x7e, (byte) 0x17, (byte) 0x03, (byte) 0xf2, (byte) 0x34, (byte) 0x31, (byte) 0x7a, (byte) 0x71, (byte) 0x02, (byte) 0x20, (byte) 0x3a, (byte) 0x35, (byte) 0x4c, (byte) 0x64, (byte) 0x4a, (byte) 0x97, (byte) 0x63, (byte) 0x87, (byte) 0x16, (byte) 0xcf, (byte) 0xdd, (byte) 0xf6, (byte) 0xd5, (byte) 0xb3, (byte) 0x9e, (byte) 0xb2, (byte) 0xfa, (byte) 0x34, (byte) 0xba, (byte) 0x99, (byte) 0xb8, (byte) 0x32, (byte) 0x22, (byte) 0x3e, (byte) 0xe1, (byte) 0x5f, (byte) 0xb4, (byte) 0x5b, (byte) 0x3f, (byte) 0x78, (byte) 0xfb, (byte) 0x8d};
	
	// Middleware keys
	
	byte[] pubExponentMW = new byte[]{(byte) 0x01, (byte) 0x00, (byte) 0x01};

	byte[] pubModulusMW = new byte[]{(byte) 0xac, (byte) 0xb8, (byte) 0x70, (byte) 0x0c, (byte) 0xe1, (byte) 0x40, (byte) 0x9a, (byte) 0x83, (byte) 0x98, (byte) 0x28, (byte) 0xaa, (byte) 0xb9, (byte) 0xc7, (byte) 0xc8, (byte) 0x82, (byte) 0xb7, (byte) 0xec, (byte) 0xb5, (byte) 0xe2, (byte) 0xa9, (byte) 0xd5, (byte) 0x2a, (byte) 0x88, (byte) 0xe4, (byte) 0x47, (byte) 0xeb, (byte) 0x65, (byte) 0xcc, (byte) 0xd9, (byte) 0x87, (byte) 0x96, (byte) 0x9d, (byte) 0x76, (byte) 0xeb, (byte) 0x78, (byte) 0x00, (byte) 0x47, (byte) 0xd8, (byte) 0xa7, (byte) 0xdc, (byte) 0x91, (byte) 0x8e, (byte) 0xf2, (byte) 0x4b, (byte) 0x88, (byte) 0x08, (byte) 0x86, (byte) 0x2f, (byte) 0x6a, (byte) 0xdc, (byte) 0x28, (byte) 0x2d, (byte) 0xd1, (byte) 0xac, (byte) 0xd1, (byte) 0x5e, (byte) 0xdd, (byte) 0xb7, (byte) 0x09, (byte) 0x11, (byte) 0x93, (byte) 0x0f, (byte) 0x2c, (byte) 0x36, (byte) 0x11, (byte) 0x0f, (byte) 0x1f, (byte) 0xe7, (byte) 0xc1, (byte) 0xe3, (byte) 0x62, (byte) 0xfc, (byte) 0x78, (byte) 0xd9, (byte) 0x30, (byte) 0x2f, (byte) 0x67, (byte) 0xfa, (byte) 0x00, (byte) 0x7e, (byte) 0x49, (byte) 0x8b, (byte) 0x72, (byte) 0x3d, (byte) 0x53, (byte) 0x4c, (byte) 0x75, (byte) 0xff, (byte) 0x07, (byte) 0xc0, (byte) 0x01, (byte) 0x57, (byte) 0x2a, (byte) 0x94, (byte) 0x39, (byte) 0x02, (byte) 0x49, (byte) 0x37, (byte) 0x8c, (byte) 0x66, (byte) 0xb8, (byte) 0x38, (byte) 0xf2, (byte) 0x4d, (byte) 0x4e, (byte) 0xfb, (byte) 0xb3, (byte) 0xbb, (byte) 0x2a, (byte) 0xfb, (byte) 0x37, (byte) 0x5d, (byte) 0xbf, (byte) 0xa0, (byte) 0x01, (byte) 0x27, (byte) 0x06, (byte) 0x0d, (byte) 0x50, (byte) 0x5f, (byte) 0xef, (byte) 0x0b, (byte) 0x58, (byte) 0xa5, (byte) 0x81, (byte) 0x5b, (byte) 0x77, (byte) 0x79, (byte) 0x70, (byte) 0x00, (byte) 0x6d, (byte) 0x49, (byte) 0xe9, (byte) 0x1e, (byte) 0x2a, (byte) 0x0e, (byte) 0x36, (byte) 0x4d, (byte) 0x99, (byte) 0x88, (byte) 0x5a, (byte) 0x47, (byte) 0xdb, (byte) 0x1e, (byte) 0x56, (byte) 0xd9, (byte) 0x63, (byte) 0xf3, (byte) 0x5a, (byte) 0x4e, (byte) 0x4d, (byte) 0x70, (byte) 0x5b, (byte) 0x1b, (byte) 0x7f, (byte) 0xab, (byte) 0x79, (byte) 0xed, (byte) 0xc7, (byte) 0xd2, (byte) 0x1d, (byte) 0x11, (byte) 0x93, (byte) 0x0d, (byte) 0x64, (byte) 0xf1, (byte) 0xed, (byte) 0x47, (byte) 0x69, (byte) 0xbc, (byte) 0x7b, (byte) 0x2a, (byte) 0xa3, (byte) 0xbe, (byte) 0x87, (byte) 0xef, (byte) 0xbd, (byte) 0xad, (byte) 0xdf, (byte) 0x5c, (byte) 0x70, (byte) 0xc4, (byte) 0x49, (byte) 0x1f, (byte) 0x9b, (byte) 0xfe, (byte) 0x43, (byte) 0x08, (byte) 0xdc, (byte) 0x81, (byte) 0xd9, (byte) 0x76, (byte) 0xb5, (byte) 0x3f, (byte) 0x2f, (byte) 0x93, (byte) 0xd6, (byte) 0x03, (byte) 0xdd, (byte) 0x1d, (byte) 0x89, (byte) 0x82, (byte) 0x0c, (byte) 0x9a, (byte) 0x0b, (byte) 0x26, (byte) 0x3e, (byte) 0xd1, (byte) 0x4a, (byte) 0x9f, (byte) 0x90, (byte) 0xad, (byte) 0x5a, (byte) 0x3f, (byte) 0x57, (byte) 0xab, (byte) 0x30, (byte) 0x1a, (byte) 0x63, (byte) 0x1a, (byte) 0xcc, (byte) 0x75, (byte) 0x0d, (byte) 0xc3, (byte) 0xc5, (byte) 0xae, (byte) 0x28, (byte) 0xda, (byte) 0x49, (byte) 0xf6, (byte) 0xe7, (byte) 0x84, (byte) 0xfc, (byte) 0x6d, (byte) 0x6e, (byte) 0x4d, (byte) 0xbc, (byte) 0x3e, (byte) 0x6b, (byte) 0xa5, (byte) 0xc2, (byte) 0xcd, (byte) 0x37, (byte) 0xba, (byte) 0x60, (byte) 0x6d, (byte) 0x74, (byte) 0xcf, (byte) 0x0b, (byte) 0xd3, (byte) 0x4a, (byte) 0x34, (byte) 0x4e, (byte) 0x55, (byte) 0x8d, (byte) 0x07};
	
	private RSAPublicKey pubKeyMiddleware;
	

	private byte[] serial = new byte[] { (byte) 0x4A, (byte) 0x61, (byte) 0x6e };
	private byte[] name = new byte[] { 0x4A, 0x61, 0x6E, 0x20, 0x56, 0x6F, 0x73, 0x73, 0x61, 0x65, 0x72, 0x74 };
	private OwnerPIN pin;

	private static byte[] pubECKeyCertificate = new byte[] { (byte) 0x30, (byte) 0x82, (byte) 0x02, (byte) 0x47,
			(byte) 0x30, (byte) 0x82, (byte) 0x01, (byte) 0x2f, (byte) 0x02, (byte) 0x04, (byte) 0xaf, (byte) 0xaa,
			(byte) 0xf1, (byte) 0x5e, (byte) 0x30, (byte) 0x0d, (byte) 0x06, (byte) 0x09, (byte) 0x2a, (byte) 0x86,
			(byte) 0x48, (byte) 0x86, (byte) 0xf7, (byte) 0x0d, (byte) 0x01, (byte) 0x01, (byte) 0x05, (byte) 0x05,
			(byte) 0x00, (byte) 0x30, (byte) 0x53, (byte) 0x31, (byte) 0x13, (byte) 0x30, (byte) 0x11, (byte) 0x06,
			(byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x03, (byte) 0x0c, (byte) 0x0a, (byte) 0x77, (byte) 0x77,
			(byte) 0x77, (byte) 0x2e, (byte) 0x4c, (byte) 0x43, (byte) 0x50, (byte) 0x2e, (byte) 0x62, (byte) 0x65,
			(byte) 0x31, (byte) 0x11, (byte) 0x30, (byte) 0x0f, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04,
			(byte) 0x0a, (byte) 0x0c, (byte) 0x08, (byte) 0x4b, (byte) 0x55, (byte) 0x4c, (byte) 0x65, (byte) 0x75,
			(byte) 0x76, (byte) 0x65, (byte) 0x6e, (byte) 0x31, (byte) 0x0d, (byte) 0x30, (byte) 0x0b, (byte) 0x06,
			(byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x07, (byte) 0x0c, (byte) 0x04, (byte) 0x47, (byte) 0x65,
			(byte) 0x6e, (byte) 0x74, (byte) 0x31, (byte) 0x0d, (byte) 0x30, (byte) 0x0b, (byte) 0x06, (byte) 0x03,
			(byte) 0x55, (byte) 0x04, (byte) 0x08, (byte) 0x0c, (byte) 0x04, (byte) 0x4f, (byte) 0x2d, (byte) 0x56,
			(byte) 0x6c, (byte) 0x31, (byte) 0x0b, (byte) 0x30, (byte) 0x09, (byte) 0x06, (byte) 0x03, (byte) 0x55,
			(byte) 0x04, (byte) 0x06, (byte) 0x13, (byte) 0x02, (byte) 0x42, (byte) 0x45, (byte) 0x30, (byte) 0x1e,
			(byte) 0x17, (byte) 0x0d, (byte) 0x31, (byte) 0x36, (byte) 0x30, (byte) 0x33, (byte) 0x32, (byte) 0x31,
			(byte) 0x30, (byte) 0x38, (byte) 0x35, (byte) 0x35, (byte) 0x34, (byte) 0x37, (byte) 0x5a, (byte) 0x17,
			(byte) 0x0d, (byte) 0x31, (byte) 0x36, (byte) 0x30, (byte) 0x36, (byte) 0x32, (byte) 0x39, (byte) 0x30,
			(byte) 0x38, (byte) 0x35, (byte) 0x35, (byte) 0x34, (byte) 0x37, (byte) 0x5a, (byte) 0x30, (byte) 0x58,
			(byte) 0x31, (byte) 0x18, (byte) 0x30, (byte) 0x16, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04,
			(byte) 0x03, (byte) 0x0c, (byte) 0x0f, (byte) 0x77, (byte) 0x77, (byte) 0x77, (byte) 0x2e, (byte) 0x4a,
			(byte) 0x61, (byte) 0x76, (byte) 0x61, (byte) 0x63, (byte) 0x61, (byte) 0x72, (byte) 0x64, (byte) 0x2e,
			(byte) 0x62, (byte) 0x65, (byte) 0x31, (byte) 0x11, (byte) 0x30, (byte) 0x0f, (byte) 0x06, (byte) 0x03,
			(byte) 0x55, (byte) 0x04, (byte) 0x0a, (byte) 0x0c, (byte) 0x08, (byte) 0x4b, (byte) 0x55, (byte) 0x4c,
			(byte) 0x65, (byte) 0x75, (byte) 0x76, (byte) 0x65, (byte) 0x6e, (byte) 0x31, (byte) 0x0d, (byte) 0x30,
			(byte) 0x0b, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x07, (byte) 0x0c, (byte) 0x04,
			(byte) 0x47, (byte) 0x65, (byte) 0x6e, (byte) 0x74, (byte) 0x31, (byte) 0x0d, (byte) 0x30, (byte) 0x0b,
			(byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x08, (byte) 0x0c, (byte) 0x04, (byte) 0x4f,
			(byte) 0x2d, (byte) 0x56, (byte) 0x6c, (byte) 0x31, (byte) 0x0b, (byte) 0x30, (byte) 0x09, (byte) 0x06,
			(byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x06, (byte) 0x13, (byte) 0x02, (byte) 0x42, (byte) 0x45,
			(byte) 0x30, (byte) 0x49, (byte) 0x30, (byte) 0x13, (byte) 0x06, (byte) 0x07, (byte) 0x2a, (byte) 0x86,
			(byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x02, (byte) 0x01, (byte) 0x06, (byte) 0x08, (byte) 0x2a,
			(byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x03, (byte) 0x01, (byte) 0x01, (byte) 0x03,
			(byte) 0x32, (byte) 0x00, (byte) 0x04, (byte) 0xfb, (byte) 0xfe, (byte) 0xb4, (byte) 0x69, (byte) 0x25,
			(byte) 0x23, (byte) 0x46, (byte) 0x94, (byte) 0x74, (byte) 0x9c, (byte) 0x62, (byte) 0xf5, (byte) 0x04,
			(byte) 0x3d, (byte) 0x01, (byte) 0x62, (byte) 0x0c, (byte) 0x58, (byte) 0x06, (byte) 0xe5, (byte) 0x65,
			(byte) 0x02, (byte) 0x29, (byte) 0x92, (byte) 0xe1, (byte) 0x36, (byte) 0x35, (byte) 0x2e, (byte) 0x67,
			(byte) 0x65, (byte) 0x51, (byte) 0x69, (byte) 0x57, (byte) 0xd1, (byte) 0xd6, (byte) 0xa5, (byte) 0xfe,
			(byte) 0xeb, (byte) 0x8e, (byte) 0xcc, (byte) 0xde, (byte) 0xb1, (byte) 0xa7, (byte) 0xd9, (byte) 0xe7,
			(byte) 0xc1, (byte) 0xbc, (byte) 0xbd, (byte) 0x30, (byte) 0x0d, (byte) 0x06, (byte) 0x09, (byte) 0x2a,
			(byte) 0x86, (byte) 0x48, (byte) 0x86, (byte) 0xf7, (byte) 0x0d, (byte) 0x01, (byte) 0x01, (byte) 0x05,
			(byte) 0x05, (byte) 0x00, (byte) 0x03, (byte) 0x82, (byte) 0x01, (byte) 0x01, (byte) 0x00, (byte) 0xda,
			(byte) 0xac, (byte) 0xf1, (byte) 0x7b, (byte) 0x91, (byte) 0x01, (byte) 0x71, (byte) 0x1e, (byte) 0x2b,
			(byte) 0x29, (byte) 0x4e, (byte) 0x94, (byte) 0x43, (byte) 0x60, (byte) 0xff, (byte) 0x8b, (byte) 0xf0,
			(byte) 0x20, (byte) 0x60, (byte) 0x73, (byte) 0xc9, (byte) 0xb6, (byte) 0xf7, (byte) 0x88, (byte) 0x65,
			(byte) 0x85, (byte) 0x21, (byte) 0x3f, (byte) 0xde, (byte) 0x15, (byte) 0xa8, (byte) 0xda, (byte) 0x81,
			(byte) 0x37, (byte) 0x18, (byte) 0xfb, (byte) 0x20, (byte) 0x9f, (byte) 0xf8, (byte) 0x36, (byte) 0xf6,
			(byte) 0xef, (byte) 0x70, (byte) 0x8e, (byte) 0xa8, (byte) 0xe6, (byte) 0xc0, (byte) 0x31, (byte) 0x0b,
			(byte) 0x18, (byte) 0x60, (byte) 0x73, (byte) 0x8c, (byte) 0x51, (byte) 0xa1, (byte) 0x4b, (byte) 0xfe,
			(byte) 0x3e, (byte) 0xc7, (byte) 0xe7, (byte) 0xf0, (byte) 0x2c, (byte) 0x62, (byte) 0x68, (byte) 0xf5,
			(byte) 0x4d, (byte) 0x3e, (byte) 0x11, (byte) 0x19, (byte) 0x4d, (byte) 0xc5, (byte) 0x80, (byte) 0x5e,
			(byte) 0x77, (byte) 0x2b, (byte) 0x49, (byte) 0x7d, (byte) 0x60, (byte) 0x72, (byte) 0xbf, (byte) 0x5e,
			(byte) 0x75, (byte) 0xae, (byte) 0x93, (byte) 0xd8, (byte) 0x04, (byte) 0xc2, (byte) 0x0f, (byte) 0x2b,
			(byte) 0xdc, (byte) 0x8f, (byte) 0x12, (byte) 0x26, (byte) 0x8b, (byte) 0x23, (byte) 0xe7, (byte) 0xc6,
			(byte) 0xca, (byte) 0x25, (byte) 0x69, (byte) 0xb2, (byte) 0xd5, (byte) 0x78, (byte) 0xec, (byte) 0x9a,
			(byte) 0x50, (byte) 0xb6, (byte) 0x4a, (byte) 0xe7, (byte) 0x6c, (byte) 0x8e, (byte) 0x43, (byte) 0x6f,
			(byte) 0x01, (byte) 0xe6, (byte) 0x39, (byte) 0x19, (byte) 0x6b, (byte) 0x18, (byte) 0xbb, (byte) 0x6b,
			(byte) 0xac, (byte) 0x98, (byte) 0x28, (byte) 0x9a, (byte) 0xd6, (byte) 0x3d, (byte) 0x36, (byte) 0xb7,
			(byte) 0x2b, (byte) 0x2f, (byte) 0xfb, (byte) 0xde, (byte) 0x89, (byte) 0x91, (byte) 0x1b, (byte) 0x85,
			(byte) 0xd2, (byte) 0x22, (byte) 0x74, (byte) 0xde, (byte) 0xd2, (byte) 0x82, (byte) 0x3e, (byte) 0x08,
			(byte) 0x34, (byte) 0xdd, (byte) 0x90, (byte) 0x95, (byte) 0xc2, (byte) 0xaa, (byte) 0x33, (byte) 0x2e,
			(byte) 0x19, (byte) 0x59, (byte) 0x0a, (byte) 0x70, (byte) 0xbc, (byte) 0x1f, (byte) 0x0e, (byte) 0xcd,
			(byte) 0x3d, (byte) 0xc5, (byte) 0x14, (byte) 0xd1, (byte) 0x81, (byte) 0x97, (byte) 0x61, (byte) 0x0a,
			(byte) 0xfa, (byte) 0xe1, (byte) 0x8a, (byte) 0x89, (byte) 0x06, (byte) 0xd4, (byte) 0xb2, (byte) 0x37,
			(byte) 0x97, (byte) 0x2a, (byte) 0x84, (byte) 0x21, (byte) 0xaf, (byte) 0x1a, (byte) 0x23, (byte) 0x12,
			(byte) 0x60, (byte) 0xe6, (byte) 0x7b, (byte) 0xc6, (byte) 0xb3, (byte) 0xfb, (byte) 0xba, (byte) 0x57,
			(byte) 0xc1, (byte) 0x39, (byte) 0x86, (byte) 0x4a, (byte) 0x89, (byte) 0xe5, (byte) 0xb4, (byte) 0x9f,
			(byte) 0xe7, (byte) 0x7c, (byte) 0x75, (byte) 0xa0, (byte) 0x9e, (byte) 0xfe, (byte) 0x58, (byte) 0x70,
			(byte) 0xeb, (byte) 0x8e, (byte) 0x46, (byte) 0xa7, (byte) 0x12, (byte) 0x51, (byte) 0x83, (byte) 0xc6,
			(byte) 0xe6, (byte) 0x30, (byte) 0x81, (byte) 0x75, (byte) 0x3c, (byte) 0xd6, (byte) 0xd5, (byte) 0xd0,
			(byte) 0xaa, (byte) 0x35, (byte) 0x78, (byte) 0x3d, (byte) 0x34, (byte) 0x77, (byte) 0x7e, (byte) 0x18,
			(byte) 0x55, (byte) 0x17, (byte) 0x88, (byte) 0x82, (byte) 0xe2, (byte) 0x01, (byte) 0x8d, (byte) 0x4e,
			(byte) 0xf9, (byte) 0x2f, (byte) 0x83, (byte) 0x37, (byte) 0x94, (byte) 0xf2, (byte) 0x13, (byte) 0x97,
			(byte) 0x46, (byte) 0x17, (byte) 0x18, (byte) 0x6a, (byte) 0x36, (byte) 0x11, (byte) 0x2d };
	
	// wCom == public EC Key
	private static byte[] wCom = new byte[] { (byte) 0x04, (byte) 0xfb, (byte) 0xfe, (byte) 0xb4, (byte) 0x69,
			(byte) 0x25, (byte) 0x23, (byte) 0x46, (byte) 0x94, (byte) 0x74, (byte) 0x9c, (byte) 0x62, (byte) 0xf5,
			(byte) 0x04, (byte) 0x3d, (byte) 0x01, (byte) 0x62, (byte) 0x0c, (byte) 0x58, (byte) 0x06, (byte) 0xe5,
			(byte) 0x65, (byte) 0x02, (byte) 0x29, (byte) 0x92, (byte) 0xe1, (byte) 0x36, (byte) 0x35, (byte) 0x2e,
			(byte) 0x67, (byte) 0x65, (byte) 0x51, (byte) 0x69, (byte) 0x57, (byte) 0xd1, (byte) 0xd6, (byte) 0xa5,
			(byte) 0xfe, (byte) 0xeb, (byte) 0x8e, (byte) 0xcc, (byte) 0xde, (byte) 0xb1, (byte) 0xa7, (byte) 0xd9,
			(byte) 0xe7, (byte) 0xc1, (byte) 0xbc, (byte) 0xbd };

	private static byte[] privECKey = new byte[] { (byte) 0xed, (byte) 0x84, (byte) 0xb4, (byte) 0xf9, (byte) 0x29,
			(byte) 0x71, (byte) 0xad, (byte) 0xcb, (byte) 0x57, (byte) 0x42, (byte) 0xaf, (byte) 0x3d, (byte) 0x6b,
			(byte) 0x4f, (byte) 0x3b, (byte) 0x48, (byte) 0x91, (byte) 0xad, (byte) 0xb1, (byte) 0x57, (byte) 0x4b,
			(byte) 0x40, (byte) 0x75, (byte) 0xae };

	// ECC domain parameters
	private static byte[] a = new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFE, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFC };

	private static byte[] p = new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFE, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF };

	private static byte[] n = new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x99, (byte) 0xDE,
			(byte) 0xF8, (byte) 0x36, (byte) 0x14, (byte) 0x6B, (byte) 0xC9, (byte) 0xB1, (byte) 0xB4, (byte) 0xD2,
			(byte) 0x28, (byte) 0x31 };

	private static byte[] b = new byte[] { (byte) 0x64, (byte) 0x21, (byte) 0x05, (byte) 0x19, (byte) 0xE5, (byte) 0x9C,
			(byte) 0x80, (byte) 0xE7, (byte) 0x0F, (byte) 0xA7, (byte) 0xE9, (byte) 0xAB, (byte) 0x72, (byte) 0x24,
			(byte) 0x30, (byte) 0x49, (byte) 0xFE, (byte) 0xB8, (byte) 0xDE, (byte) 0xEC, (byte) 0xC1, (byte) 0x46,
			(byte) 0xB9, (byte) 0xB1 };

	private static byte[] G = new byte[] { (byte) 0x04, (byte) 0x18, (byte) 0x8D, (byte) 0xA8, (byte) 0x0E, (byte) 0xB0,
			(byte) 0x30, (byte) 0x90, (byte) 0xF6, (byte) 0x7C, (byte) 0xBF, (byte) 0x20, (byte) 0xEB, (byte) 0x43,
			(byte) 0xA1, (byte) 0x88, (byte) 0x00, (byte) 0xF4, (byte) 0xFF, (byte) 0x0A, (byte) 0xFD, (byte) 0x82,
			(byte) 0xFF, (byte) 0x10, (byte) 0x12, (byte) 0x07, (byte) 0x19, (byte) 0x2B, (byte) 0x95, (byte) 0xFF,
			(byte) 0xC8, (byte) 0xDA, (byte) 0x78, (byte) 0x63, (byte) 0x10, (byte) 0x11, (byte) 0xED, (byte) 0x6B,
			(byte) 0x24, (byte) 0xCD, (byte) 0xD5, (byte) 0x73, (byte) 0xF9, (byte) 0x77, (byte) 0xA1, (byte) 0x1E,
			(byte) 0x79, (byte) 0x48, (byte) 0x11 };

	private RSAPrivateKey privKey;

	private short offset = (short) 0;

	private AESKey sessionKey = null;
	
	private boolean isMWauthenticated = false;
	private byte[] initChallenge;
	private byte challengeP1;
	private byte challengeP2;
	
	private byte[] shopEntries;
	private short shopEntryOffset = (short) 0;
	private byte[] selectedPseudoCertificate;
	
	/* register variables */
	byte[] pseudonymTemp, certificateTemp, shopNameTemp;

	private byte[] encryptedCertificateTemp;

	private short selectedShopEntryOffset = (short) -1;

	private short numberOfLogs = (short) 0;

	private byte[] logs = new byte[600]; //max number of logs is 20 and a log is 30 bytes long, -> 600 bytes long

	private IdentityCard() {
		/*
		 * During instantiation of the applet, all objects are created. In this
		 * example, this is the 'pin' object.
		 */
		isMWauthenticated = false;
		pin = new OwnerPIN(PIN_TRY_LIMIT, PIN_SIZE);
		pin.update(new byte[] { 0x01, 0x02, 0x03, 0x04 }, (short) 0, PIN_SIZE);
		

		/* Build private RSA Key */
		short offset = 0;
		short keySizeInBytes = 64;
		short keySizeInBits = (short) (keySizeInBytes * 8);
		privKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, keySizeInBits, false);
		privKey.setExponent(privExponent, offset, keySizeInBytes);
		privKey.setModulus(privModulus, offset, keySizeInBytes);
		
		/* Build public RSA Key of Middleware */
		offset = 0;
		keySizeInBytes = 256;
		keySizeInBits = (short) (keySizeInBytes * 8);
		pubKeyMiddleware = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, keySizeInBits, false);
		pubKeyMiddleware.setExponent(pubExponentMW, offset, (short) 3);
		pubKeyMiddleware.setModulus(pubModulusMW, offset, keySizeInBytes);
		

		/*
		 * This method registers the applet with the JCRE on the card.
		 */

		register();
	}

	/*
	 * This method is called by the JCRE when installing the applet on the card.
	 */
	public static void install(byte bArray[], short bOffset, byte bLength) throws ISOException {
		new IdentityCard();
	}

	/*
	 * If no tries are remaining, the applet refuses selection. The card can,
	 * therefore, no longer be used for identification.
	 */

	public boolean select() {
		if (pin.getTriesRemaining() == 0)
			return false;
		return true;
	}

	/*
	 * This method is called when the applet is selected and an APDU arrives.
	 */

	public void process(APDU apdu) throws ISOException {
		// A reference to the buffer, where the APDU data is stored, is
		// retrieved.
		byte[] buffer = apdu.getBuffer();

		// If the APDU selects the applet, no further processing is required.
		if (this.selectingApplet())
			return;

		// Check whether the indicated class of instructions is compatible with
		// this applet.
		if (buffer[ISO7816.OFFSET_CLA] != IDENTITY_CARD_CLA)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		// A switch statement is used to select a method depending on the
		// instruction
		switch (buffer[ISO7816.OFFSET_INS]) {
		case VALIDATE_PIN_INS:
			validatePIN(apdu);
			break;
		case GET_SERIAL_INS:
			getSerial(apdu);
			break;
		case GET_NAME_INS:
			getName(apdu);
			break;
		case CHALLENGE_INS:
			challenge(apdu);
			break;
//		case SET:
//			byte[] buffer1 = apdu.getBuffer();
//			apdu.setIncomingAndReceive();
//			test = new byte[1];
//			Util.arrayCopy(buffer1, ISO7816.OFFSET_CDATA, test, (short) 0, (short) 1);
//			break;
//		case PULL:
//			apdu.setOutgoing();
//			apdu.setOutgoingLength((short) test.length);
//			apdu.sendBytesLong(test, (short) 0, (short) test.length);
//			break;
		case ENCRYPT_BYTES_WITH_SESSION_KEY:
			encryptWithSessionKey(apdu);
			break;
//		case DECRYPT_BYTES_WITH_SESSION_KEY:
//			decryptWithSessionKey(apdu);
//			break;
		case GET_EC_CERTIFICATE:
			getPublicECCertificate(apdu);
			break;
		// case GET_EC_CERTIFICATE_SIZE:
		// getECCertificateLength(apdu);
		// break;
		case TEST:
			test(apdu); break;
		case CLOSE_SECURE_CONNECTION:
			sessionKey = null;
			break;
		case CLEAR_OFFSET_INS: {
			offset = 0;
			break;
		}
		case GENERATE_SESSION_KEY:
			generateSessionKey(apdu);
			break;
		case REGISTER_SHOP_PSEUDONYM:
			registerShopPseudonym(apdu); break;
		case REGISTER_SHOP_CERTIFICATE_PART1:
			registerShopCertificate(apdu, (short) 1); break;
		case REGISTER_SHOP_CERTIFICATE_PART2:
			registerShopCertificate(apdu, (short) 2); break;
		case REGISTER_SHOP_CERTIFICATE_PART3:
			registerShopCertificate(apdu, (short) 3); break;
		case REGISTER_SHOP_NAME:
			registerShopName(apdu); break;
		case REGISTER_SHOP_COMPLETE:
			registerShopComplete(apdu); break;
		case INIT_CHALLENGE:
			challenge(apdu); break;
		case CHALLENGE_ACCEPTED:
			challengeIsAccepted(apdu); break;
		case GET_NEXT_CHALLENGE:
			getNextChallenge(apdu); break;
		case GET_CURRENT_CHALLENGE:
			getCurrentChallenge(apdu); break;
		case GET_PSEUDONYM_CERTIFICATE_PART1:
			getPseudonymCertificate(apdu, (short) 1); break;
		case GET_PSEUDONYM_CERTIFICATE_PART2:
			getPseudonymCertificate(apdu, (short) 2); break;
		case GET_PSEUDONYM_CERTIFICATE_PART3:
			getPseudonymCertificate(apdu, (short) 3); break;
		case CHANGE_LP:
			changeLP(apdu); break;
		case GET_LP:
			getLP(apdu); break;
		case GET_NUMBER_OF_LOGS:{
			byte[] numLogs = shortToByteArray((short) numberOfLogs);
			sendBytesNotEncrypted(apdu, numLogs);
			break;
		}
		case GET_NEXT_LOG:
			getNextLog(apdu);
			break;
		case CLEAR_LOGS:
			clearLogs(apdu); break;			
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	private void clearLogs(APDU apdu) {
		logs = new byte[(short) 600];
		numberOfLogs = (short) 0;
	}

	private void getNextLog(APDU apdu) {
		checkChallengeWithoutBuffer(apdu);
		// Fetch log at the end of logs
		// So we can decrement the number of logs
		// without needing an extra parameter to track the number of fetched logs
		
		// 1. Fetch last log from logs
		if(numberOfLogs==(short) 0) return;
		short beginLastLog = (short) ((numberOfLogs-1)*30);
		byte[] lastLog = new byte[(short) 30];
		Util.arrayCopy(logs, (short) beginLastLog, lastLog, (short) 0, (short) 30); 
		
		// 2. Encrypt with sessionkey and send back
		byte[] encryptedLog = encryptWithSessionKey(lastLog);
		sendBytesNotEncrypted(apdu, encryptedLog);
		
		// 3. Decrement number of logs
		numberOfLogs--;
		
	}


	/*
	 * This method will change the LP by an amount specified in the apdu data
	 * this for the shop who's been selected earlier by the 'getPseudonymCertificate'
	 * 
	 * If LP will be < 0 after transaction the transaction will fail
	 * If succeeded, an 0x00 byte will be send encrypted by the sessionkey (not MW encrypted)
	 * 
	 * If failed an 0x01 byte will be send (encrypted by sessionkey)
	 * 
	 */

	private void changeLP(APDU apdu) {
		// 1.	get amount and parse to short
		byte[] data = receiveBytesAndCheckChallenge(apdu);
		byte[] am = decryptWithSessionKey(data);
		short amount = bytesToShort(am[0], am[1]);
		
		// 2.	get LP for selected shop entry (begins at 439)
		byte[] lp = new byte[(short) 2];
		Util.arrayCopy(selectedShopEntry, (short) 439, lp, (short) 0, (short) 2);
		short LP = (short) bytesToShort(lp[0], lp[1]);

		
		// 3.	Check if LP won't get lower than 0
		short LPAfterTransaction  = (short) ((short) ((short) LP) + ((short) amount));
		if(LPAfterTransaction < (short) 0) sendBytesNotEncrypted(apdu, encryptWithSessionKey(new byte[]{0x01}));
		
		
		// 4.	OK everything looks fine, let's do this
		//		The amount can also be negative so we take the sum of the current LP and the amount
		LP= (short) (LP + amount);
		
		// 5.	Save new LP to shopEntries
		byte[] newLP = shortToByteArray(LP);
		Util.arrayCopy(newLP, (short) 0, shopEntries, (short) (selectedShopEntryOffset+(short)439), (short) 2);
		
		
		// 6.	Log transaction
		byte[] pseudonym = new byte[(short) 26];
		Util.arrayCopy(selectedShopEntry, (short) 0, pseudonym, (short) 0, (short) 26);
		log(pseudonym, shortToByteArray(amount), newLP);
		
		// 7.	discard selectedShopEntry and offset
		selectedShopEntry = null;
		selectedShopEntryOffset = (short) -1;
		
		// 8.	Send succeeded message ecrypted by sessionkey back
		sendBytesNotEncrypted(apdu, encryptWithSessionKey(new byte[]{0x00}));
	}

	/*
	 * This method wil save the transaction to a log byte[]
	 */

	private void log(byte[] pseudonym, byte[] amount, byte[] newLP) {
		short offset = (short) ((short) numberOfLogs*((short) 30)); // a log is 30 bytes long
		Util.arrayCopy(pseudonym, (short) 0, logs, (short) offset, (short) 26); 
		Util.arrayCopy(amount, (short) 0, logs, (short) ((short) offset+26), (short) 2); 
		Util.arrayCopy(newLP, (short) 0, logs, (short) ((short) offset+28), (short) 2); 
		numberOfLogs ++;		
	}

	/*
	 * This method will load and send the pseudonym certificate for a particular shop
	 * Steps:
	 * 	1.	load shop entry for selected shop
	 * 	2.	load certificate
	 * 	3.	encrypt certificate
	 * 	4. 	based on which part send piece of encrypted certificate
	 * 	
	 */
	private void getPseudonymCertificate(APDU apdu, short part){
		// 1. if part 1 get full certificate
		if(part==1){
			selectedPseudoCertificate = new byte[(short) 512]; //512 because encryption works with blocks of 128
			
			
			// 1.a load shop entry for shopname
			byte[] shopName = receiveBytesAndCheckChallenge(apdu);
			
			boolean found = selectShopEntry(shopName);
			
			// 1.b load certificate from selected shop entry
			//		certificate starts at index 26, size is 413 bytes
			Util.arrayCopy(selectedShopEntry, (short) 26, selectedPseudoCertificate, (short) 0, (short) 413);
			
			// 1.c encrypt selected certificate
			byte[] encryptedData = encryptWithSessionKey512(selectedPseudoCertificate);
			selectedPseudoCertificate = new byte[512];
			Util.arrayCopy(encryptedData, (short) 0, selectedPseudoCertificate, (short) 0, (short) 512);
			
			// 1.d send first 200 bytes back
			byte[] dataToSend = new byte[(short) 200];
			Util.arrayCopy(selectedPseudoCertificate, (short) 0, dataToSend, (short) 0, (short) 200);
			sendBytesNotEncrypted(apdu, dataToSend);
		}
		// 2. based on which part send piece of certificate
		if(part==2){
			receiveBytes(apdu);
			byte[] d = new byte[(short) 200];
			Util.arrayCopy(selectedPseudoCertificate, (short) 200, d, (short) 0, (short) 200);
			sendBytesNotEncrypted(apdu, d);
		}
		if(part==3){
			receiveBytes(apdu);
			byte[] dataToSend = new byte[(short) 112];
			Util.arrayCopy(selectedPseudoCertificate, (short) 400, dataToSend, (short) 0, (short) 112);
			sendBytesNotEncrypted(apdu, dataToSend);
		}
		
	}


	private void sendBytesNotEncrypted(APDU apdu, byte[] dataToSend) {
		apdu.setOutgoing();
		apdu.setOutgoingLength((short) dataToSend.length);
		apdu.sendBytesLong(dataToSend, (short) 0, (short) dataToSend.length);
	}
	
	private void getLP(APDU apdu) {
		byte[] shopName = receiveBytesAndCheckChallenge(apdu);
		selectShopEntry(shopName);
		// location of lp: 439
		byte[] lp = new byte[2];
		Util.arrayCopy(selectedShopEntry, (short) 0, lp, (short) 0, (short) 2);
		SendAndEncryptWithSessionKey(apdu, lp);
	}

	/* 
	 * This method searches for the shop entry for a particular shop
	 * And if found places the content in selectedShopEntry
	 */
	private boolean selectShopEntry(byte[] shopName) {
		// place of shopname: 441 - 500 in every entry
		for(short offset=0; offset<(short) shopEntries.length; offset+=500){
			byte[] selectedShopName = new byte[(short) 59];// 59 = 500 - 441
			Util.arrayCopy(shopEntries, (short) (offset+441), selectedShopName, (short) 0, (short) 59);
			byte[] trimmedShopName = removeNullBytes(selectedShopName);
			if(shopName.length==trimmedShopName.length){
				if(Util.arrayCompare(trimmedShopName, (short) 0, shopName, (short) 0, (short) shopName.length)==0x00){
					// Finally found that shit!
					selectedShopEntryOffset  = offset;
					selectedShopEntry = new byte[(short) 500];
					Util.arrayCopy(shopEntries, (short) offset, selectedShopEntry, (short) 0, (short) 500);
					return true;
				}
			}
		}
		return false;
	}

	private void getSerial(APDU apdu) {
		if (!pin.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else {
		checkChallengeWithoutBuffer(apdu);
		SendAndEncryptWithSessionKey(apdu, serial);
		}
		
	}

	private void getCurrentChallenge(APDU apdu) {
		sendBytesEncryptedForMW(apdu, new byte[]{challengeP1, challengeP2}, (short) 2);
		
	}

	private void getNextChallenge(APDU apdu) {
		byte[] nextChallenge = getRandomByteArray((short) 2);
		challengeP1 = nextChallenge[0];
		challengeP2 = nextChallenge[1];
		sendBytesEncryptedForMW(apdu, nextChallenge, (short) nextChallenge.length);
		
	}

	private void challengeIsAccepted(APDU apdu) {
		byte[] challengeReceived = receiveBytes(apdu);
		if(Util.arrayCompare(initChallenge, (short) 0, challengeReceived, (short) 0, (short) challengeReceived.length)==(byte) 0){
			isMWauthenticated = true;
			getNextChallenge(apdu);
		}else{
			pin.reset();
			ISOException.throwIt(CHALLENGE_NOT_ACCEPTED);
		}
	}

	/*
	 * This method is used to authenticate the owner of the card using a PIN
	 * code, first the MW must have passed an authentication
	 */
	private void validatePIN(APDU apdu) {
		if(!isMWauthenticated) ISOException.throwIt(MW_MUST_BE_AUTHENTICATED);
		byte[] pinBytesWithNull = receiveBytesEncryptedByMW(apdu);
		byte[] pinBytes = removeNullBytes(pinBytesWithNull);

		if (pinBytes.length == PIN_SIZE) {
			if (pin.check(pinBytes, (short) 0, PIN_SIZE) == false)
				ISOException.throwIt(SW_VERIFICATION_FAILED);
		} else
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	}

	/*
	 * This method checks whether the user is authenticated and sends the serial
	 * number.
	 */




	private void getName(APDU apdu) {
		// If the pin is not validated, a response APDU with the
		// 'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
		if (!pin.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else {
			// This sequence of three methods sends the data contained in
			// 'serial' with offset '0' and length 'serial.length'
			// to the host application.
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) name.length);
			apdu.sendBytesLong(name, (short) 0, (short) name.length);
		}
	}

	public void challenge(APDU apdu) {
			initChallenge = getRandomByteArray((short) 64);
			sendBytesEncryptedForMW(apdu, initChallenge, (short) initChallenge.length); 
	}

	private void getECCertificateLength(APDU apdu) {
		short length = (short) pubECKeyCertificate.length;
		byte[] lengthInBytes = shortToByteArray(length);
		apdu.setOutgoing();
		apdu.setOutgoingLength((short) lengthInBytes.length);
		apdu.sendBytesLong(lengthInBytes, (short) 0, (short) lengthInBytes.length);
	}

	private void getPublicECCertificate(APDU apdu) {
		if (!pin.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else {
			byte[] buffer = apdu.getBuffer();
			apdu.setOutgoing();
			short numBytesToRead = (short) (buffer[ISO7816.OFFSET_P1] & (short) 0xFF);
			/*
			 * src - source byte array 
			 * srcOff - offset within source byte array to start copy from 
			 * dest - destination byte array 
			 * destOff - offset within destination byte array to start copy into 
			 * length - byte length to be copied
			 */
			byte[] toSend = new byte[numBytesToRead];
			Util.arrayCopy(pubECKeyCertificate, offset, toSend, (short) 0, numBytesToRead);
			apdu.setOutgoingLength(numBytesToRead);
			apdu.sendBytesLong(toSend, (short) 0, numBytesToRead);
			offset += numBytesToRead;
		}

	}

	private void generateSessionKey(APDU apdu) {
		byte[] pubKeyOtherParty = receiveBytesAndCheckChallenge(apdu);
//		byte[] buffer = apdu.getBuffer();
//		apdu.setIncomingAndReceive();
//		short length = apdu.getIncomingLength();
//		byte[] pubKeyOtherParty = new byte[length];
//		Util.arrayCopy(buffer, (short) ISO7816.OFFSET_CDATA, pubKeyOtherParty, (short) 0, (short) length);
		
	
		byte[] sessionKeyBytes = getSessionKey(pubKeyOtherParty);
		
		this.sessionKey = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        this.sessionKey.setKey(sessionKeyBytes, (short)0);
        
		apdu.setOutgoing();
		apdu.setOutgoingLength((short) sessionKeyBytes.length);
		apdu.sendBytesLong(sessionKeyBytes, (short) 0, (short) sessionKeyBytes.length);
		
	}

	

	public static byte[] getSessionKey(byte[] pubKeyOtherParty) {

		KeyAgreement keyAgr = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
		keyAgr.init(getCommonKeyPrivate());

		byte[] publicData = pubKeyOtherParty;
		short publicLength = (short) pubKeyOtherParty.length;
		byte[] secret = new byte[250];
		// generateSecret(byte[] publicData, short publicOffset, short
		// publicLength, byte[] secret, short secretOffset)
		short secretLength = keyAgr.generateSecret(publicData, (short) 0, publicLength, secret, (short) 0);
		byte[] sessionKey = new byte[secretLength];

		// arrayCopy(byte[] src, short srcOff, byte[] dest, short destOff, short
		// length)
		Util.arrayCopy(secret, (short) 0, sessionKey, (short) 0, secretLength);
		return sessionKey;

	}

	public static short bytesToShort(byte b1, byte b2){
		return Util.makeShort(b1, b2);
	}
	public static byte[] shortToByteArray(short s) {
		// setShort(byte[] bArray, short bOff, short sValue)
		byte[] shortByte = new byte[2];
		Util.setShort(shortByte, (short) 0, s);
		return shortByte;
	}

	public static void setDomainParameters(ECKey key) {
		key.setA(a, (short) 0, (short) a.length);
		key.setB(b, (short) 0, (short) b.length);
		key.setR(n, (short) 0, (short) n.length);
		key.setK((short) 1);
		key.setG(G, (short) 0, (short) G.length);
		key.setFieldFP(p, (short) 0, (short) p.length);
	}

	public static PublicKey getCommonKeyPublic() {
		ECPublicKey pubKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC,
				KeyBuilder.LENGTH_EC_FP_192, false);
		setDomainParameters(pubKey);
		pubKey.setW(wCom, (short) 0, (short) wCom.length);
		return pubKey;
	}

	public static ECPrivateKey getCommonKeyPrivate() {
		ECPrivateKey privKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE,
				KeyBuilder.LENGTH_EC_FP_192, false);
		privKey.setS(privECKey, (short) 0, (short) privECKey.length);
		setDomainParameters(privKey);
		return privKey;
	}
	
	private byte[] removeNullBytes(byte[] data) {
		short length = (short) data.length;
		short i;
		for(i = 0; i< length ;i++){
			if(data[i]==0x00) break;
		}
		byte[] cleanedData = new byte[i];
		Util.arrayCopy(data, (short) 0, cleanedData, (short) 0, i);
		return cleanedData;
	}
	
	private void sendBytesEncryptedForMW(APDU apdu, byte[] data, short dataLen){
		Cipher asymCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
		asymCipher.init(pubKeyMiddleware, Cipher.MODE_ENCRYPT);
		byte[] encryptedData = new byte[256];
		
		byte[] dataToEncrypt = new byte[64];
		
		Util.arrayCopy(data, (short) 0, dataToEncrypt, (short) 0, (short) data.length);
				
		asymCipher.doFinal(data, (short) 0, (short) data.length, encryptedData, (short) 0);
		
		apdu.setOutgoing();
		apdu.setOutgoingLength((short) encryptedData.length);
		apdu.sendBytesLong(encryptedData, (short) 0, (short) encryptedData.length);
	}
	
	private byte[] receiveBytesEncryptedByMW(APDU apdu){
		byte[] buffer = apdu.getBuffer();
		apdu.setIncomingAndReceive();
		short dataLen = apdu.getIncomingLength();
		
		byte[] encryptedData = new byte[dataLen];
		
		Util.arrayCopy(buffer, (short) ISO7816.OFFSET_CDATA, encryptedData, (short) 0, dataLen);
		
		
		Cipher asymCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
		asymCipher.init(privKey, Cipher.MODE_DECRYPT);
		
		byte[] decryptedData = new byte[256];
		
		short length = asymCipher.doFinal(encryptedData, (short) 0, (short) dataLen, decryptedData, (short) 0);
		
		byte[] returnData = new byte[length];
		Util.arrayCopy(decryptedData, (short) 0, returnData, (short) 0, length);
		
		return decryptedData;
	}
	
	private byte[] receiveBytes(APDU apdu){
		byte[] buffer = apdu.getBuffer();
		apdu.setIncomingAndReceive();
		short dataLen = apdu.getIncomingLength();
		
		byte[] data = new byte[dataLen];
		
		Util.arrayCopy(buffer, (short) ISO7816.OFFSET_CDATA, data, (short) 0, dataLen);
		return data;
	}
	
	private void checkChallengeWithoutBuffer(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		apdu.setIncomingAndReceive();
		
		byte p1 = buffer[ISO7816.OFFSET_P1];
		byte p2 = buffer[ISO7816.OFFSET_P2];
		
		if(((byte) p1 == (byte) challengeP1) && ((byte) p2 == (byte) challengeP2)){
			clearChallenges();
		}else{
			pin.reset();
			ISOException.throwIt(CHALLENGE_NOT_ACCEPTED);
		}
		
	}
	
	private byte[] checkChallenge(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		apdu.setIncomingAndReceive();
		
		byte p1 = buffer[ISO7816.OFFSET_P1];
		byte p2 = buffer[ISO7816.OFFSET_P2];
		
		if(((byte) p1 == (byte) challengeP1) && ((byte) p2 == (byte) challengeP2)){
			clearChallenges();
			return buffer;
		}
		
		pin.reset();
		ISOException.throwIt(CHALLENGE_NOT_ACCEPTED);
		
		return null;
	}
	
	private byte[] receiveBytesAndCheckChallenge(APDU apdu) {
		byte[] buffer = checkChallenge(apdu);
		short dataLen = apdu.getIncomingLength();
		byte[] data = new byte[dataLen];
		Util.arrayCopy(buffer, (short) ISO7816.OFFSET_CDATA, data, (short) 0, dataLen);
		return data;
	}
	
	private void clearChallenges() {
		byte[] nextChallenge = getRandomByteArray((short) 2);
		challengeP1 = nextChallenge[0];
		challengeP2 = nextChallenge[1];
		
	}

	private void test(APDU apdu) {
		byte[] data = receiveBytes(apdu);		
		sendBytesEncryptedForMW(apdu, data, (short) data.length); 
	}
	
	
	


	/************ SHOP REGISTRATION METHODS *****************/
	/* save temp register variables in shop entry */
	//TODO check if shop already on the card
	private void registerShopComplete(APDU apdu) {
		if(shopEntryOffset==0){
			// first shop!
			shopEntries = new byte[(short) 500];
			shopEntryOffset = 500;
			
			Util.arrayCopy(pseudonymTemp, (short) 0, shopEntries, (short) 0, (short) 26);
			Util.arrayCopy(certificateTemp, (short) 0, shopEntries, (short) 26, (short) 413);
			byte[] lp = shortToByteArray((short) 0);
			Util.arrayCopy(lp, (short) 0, shopEntries, (short) 439, (short) 2);
			Util.arrayCopy(shopNameTemp, (short) 0, shopEntries, (short) 441, (short) shopNameTemp.length);
			
		}else{
			// Make free space for extra 500 bytes
			byte[] shopEntriesTemp = new byte[(short) (shopEntryOffset+500)];
			Util.arrayCopy(shopEntries, (short) 0, shopEntriesTemp, (short) 0, (short) shopEntryOffset);
			shopEntries = new byte[(short) (shopEntryOffset+500)];
			Util.arrayCopy(shopEntriesTemp, (short) 0, shopEntries, (short) 0, (short) shopEntryOffset);
			
			// Fill with new shop
			Util.arrayCopy(pseudonymTemp, (short) 0, shopEntries, (short) shopEntryOffset, (short) 26);
			Util.arrayCopy(certificateTemp, (short) 0, shopEntries, (short) (shopEntryOffset + 26), (short) 413);
			byte[] lp = shortToByteArray((short) 0);
			Util.arrayCopy(lp, (short) 0, shopEntries, (short) (shopEntryOffset+439), (short) 2);
			Util.arrayCopy(shopNameTemp, (short) 0, shopEntries, (short) (shopEntryOffset + 441), (short) shopNameTemp.length);
			
			
			shopEntryOffset += 500;
		}
	}
	
	private void registerShopName(APDU apdu) {
		// doesn't need decrypting with sessionkey
		shopNameTemp = receiveBytes(apdu);
	}

	private void registerShopCertificate(APDU apdu, short part) {
		byte[] data = receiveBytes(apdu);
		if(part==1){
			// first 200 bytes have arrived
			encryptedCertificateTemp = new byte[512];
			Util.arrayCopy(data, (short) 0, encryptedCertificateTemp, (short) 0, (short) 200);
			
		}else if(part==2){
			// next 200 bytes have arrived
			Util.arrayCopy(data, (short) 0, encryptedCertificateTemp, (short) 200, (short) 200);
			
		}else if(part==3){
			// last 112 bytes have arrived
			// now the decryption can take place
			Util.arrayCopy(data, (short) 0, encryptedCertificateTemp, (short) 400, (short) 112);
			byte[] decryptedData = decryptWithSessionKey(encryptedCertificateTemp);
			
			// extract correct length of certificate
			certificateTemp = new byte[413];
			Util.arrayCopy(decryptedData, (short) 0, certificateTemp, (short) 0, (short) 413);
		}
		
		
	}

	private void registerShopPseudonym(APDU apdu) {
		byte[] data = receiveBytes(apdu);
		
		// needs be decrypting first
		byte[] decryptedData = decryptWithSessionKey(data);
		
		// extract correct length of psuedonym
		pseudonymTemp = new byte[pseudonymLen]; 
		Util.arrayCopy(decryptedData, (short) 0, pseudonymTemp, (short) 0, pseudonymLen);
		sendBytesEncryptedForMW(apdu, pseudonymTemp, pseudonymLen);
	}

	
	/************ ENCRYPTION AND DECRYPTION WITH SESSIONKEY METHODS *****************/
	
	private void SendAndEncryptWithSessionKey(APDU apdu, byte[] data) {
		if(sessionKey==null) ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
		
		byte[] encryptedData = encryptWithSessionKey(data);
		
		apdu.setOutgoing();
		apdu.setOutgoingLength((short) encryptedData.length);
		apdu.sendBytesLong(encryptedData, (short) 0, (short) encryptedData.length);	
	}
	
	private void encryptWithSessionKey(APDU apdu) {
		if(sessionKey==null) ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
		byte[] data = receiveBytes(apdu);
		
		byte[] encryptedData = encryptWithSessionKey(data);
		
		apdu.setOutgoing();
		apdu.setOutgoingLength((short) encryptedData.length);
		apdu.sendBytesLong(encryptedData, (short) 0, (short) encryptedData.length);	
	}
	
	private void decryptWithSessionKey(APDU apdu) {
		if(sessionKey==null) ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
		byte[] buffer = apdu.getBuffer();
		short length = apdu.setIncomingAndReceive();
		byte[] data = new byte[length];
		Util.arrayCopy(buffer, (short) ISO7816.OFFSET_CDATA, data, (short) 0, length);
		byte[] decryptedData = decryptWithSessionKey(data);
		
		apdu.setOutgoing();
		apdu.setOutgoingLength((short) decryptedData.length);
		apdu.sendBytesLong(decryptedData, (short) 0, (short) decryptedData.length);	
	}

	private byte[] encryptWithSessionKey(byte[] data) {
		Cipher cipherSYM = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
		cipherSYM.init(this.sessionKey, Cipher.MODE_ENCRYPT);
		byte[] dataToEncrypt = new byte[128];
		Util.arrayCopy(data, (short) 0, dataToEncrypt, (short) 0, (short) data.length);
		byte[] encryptedData = new byte[128];
		cipherSYM.doFinal(dataToEncrypt, (short)0, (short)128, encryptedData, (short)0);
		return encryptedData;
	}
	
	private byte[] encryptWithSessionKey512(byte[] data) {
		Cipher cipherSYM = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
		cipherSYM.init(this.sessionKey, Cipher.MODE_ENCRYPT);
		byte[] dataToEncrypt = new byte[512];
		Util.arrayCopy(data, (short) 0, dataToEncrypt, (short) 0, (short) data.length);
		byte[] encryptedData = new byte[512];
		cipherSYM.doFinal(dataToEncrypt, (short)0, (short)512, encryptedData, (short)0);
		return encryptedData;
	}
	
	private byte[] decryptWithSessionKey(byte[] encryptedData) {
		Cipher cipherSYM = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
		cipherSYM.init(this.sessionKey, Cipher.MODE_DECRYPT);
		byte[] dataToDecrypt = new byte[512];
		Util.arrayCopy(encryptedData, (short) 0, dataToDecrypt, (short) 0, (short) encryptedData.length);
		byte[] decryptedData = new byte[512];
		cipherSYM.doFinal(dataToDecrypt, (short)0, (short) 512, decryptedData, (short)0);
		return decryptedData;
	}
	
	private byte[] getRandomByteArray(short s) {
		byte[] rndByte = new byte[s];
		RandomData rnd = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
		rnd.generateData(rndByte, (short) 0, (short)s);
		return rndByte;
	}

}
