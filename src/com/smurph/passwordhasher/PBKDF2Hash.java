/**
 * Copyright (c) 2012 Benjamin Murphy
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.smurph.passwordhasher;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import com.smurph.passwordhasher.exceptions.Base64DecodingException;

public class PBKDF2Hash {

	/**
	 * Minimum rounds 1000 anything less will be set as 1000.<br>
	 * The higher the number the longer the encryption will take.
	 * 
	 * @param iterations
	 *            The number of rounds to to use during the <tt>String</tt>
	 *            encryption.
	 * 
	 */
	public PBKDF2Hash(int iterations) {
		this(iterations, 0x0A0);
	}

	/**
	 * Minimum rounds 1000 anything less will be set as 1000.<br>
	 * The higher the number the longer the encryption will take.
	 * 
	 * @param iterations
	 *            The number of rounds to to use during the <tt>String</tt>
	 *            encryption.
	 * @param keyLength
	 *            The length of the key genreated to hash the password default is 160
	 * 
	 */
	public PBKDF2Hash(int iterations, int keyLength) {
		this(iterations, keyLength, EncoderType.WEB_SAFE_BASE64);
	}

	/**
	 * Minimum rounds 1000 anything less will be set as 1000.<br>
	 * The higher the number the longer the encryption will take.
	 * 
	 * @param iterations
	 *            The number of rounds to to use during the <tt>String</tt>
	 *            encryption.
	 * @param keyLength
	 *            The length of the key genreated to hash the password default is 160
	 * @param encoderType
	 *            Pick one of the values from {@link EncoderType} default is {@link EncoderType#WEB_SAFE_BASE64}
	 */
	public PBKDF2Hash(int iterations, int keyLength, int encoderType) {
		// Set the number of rounds preformed during the hashing
		if (iterations >= mMinIterations)
			this.mIterations = iterations;
		else
			this.mIterations = mMinIterations;
		
		// Set the length of the key used during hashing
		if (keyLength<160)
			mDerivedKeyLength = 0x0A0;
		else
			mDerivedKeyLength = keyLength;

		// This goes a long with the EncoderType interface
		switch (encoderType) {
		case EncoderType.HEX:
			this.mEncoderType = EncoderType.HEX;
			break;
		case EncoderType.WEB_SAFE_BASE64:
			this.mEncoderType = EncoderType.WEB_SAFE_BASE64;
			break;

		default:
			this.mEncoderType = EncoderType.WEB_SAFE_BASE64;
		}
	}

	/**
	 * This will generate a {@link SecureRandom} with the SHA1PRNG algorithm <br>
	 * then return an 64 bit (8 byte) salt.
	 * 
	 * @return 64 bit (8 byte) salt
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException 
	 */
	public byte[] generateSalt() throws NoSuchAlgorithmException, NoSuchProviderException {
		return generateSalt(8);
	}
	
	/**
	 * @param saltLength The length of the byte[] 
	 * @return byte[] salt of said length. 
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException 
	 */
	public byte[] generateSalt(int saltLength) throws NoSuchAlgorithmException, NoSuchProviderException {
		SecureRandom random = SecureRandom.getInstance(mSecRandomAlgorithm);
		byte[] salt = new byte[saltLength];
		random.nextBytes(salt);
		return salt;
	}
	
	/**
	 * 
	 * @param attemptedPassword
	 * @param hashedPassword
	 * @param salt
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws Base64DecodingException
	 * @throws NoSuchProviderException
	 */
	public boolean verifyPassword(String attemptedPassword, String hashedPassword, String salt)
			throws NoSuchAlgorithmException, InvalidKeySpecException, Base64DecodingException, NoSuchProviderException {

		switch (mEncoderType) {
		case EncoderType.HEX:
			return verifyPassword(attemptedPassword, hashedPassword, HexCoder.toByte(salt));
		case EncoderType.WEB_SAFE_BASE64:
			return verifyPassword(attemptedPassword, hashedPassword, Base64Coder.decodeWebSafe(salt));

		default:
			return false;
		}
	}

	/**
	 * 
	 * @param attemptedPassword
	 * @param encryptedPassword
	 * @param salt
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws Base64DecodingException
	 * @throws NoSuchProviderException 
	 */
	public boolean verifyPassword(String attemptedPassword, String hashedPassword, byte[] salt)
			throws NoSuchAlgorithmException, InvalidKeySpecException, Base64DecodingException, NoSuchProviderException {

		switch (mEncoderType) {
		case EncoderType.HEX:
			return authenticate(attemptedPassword, HexCoder.toByte(hashedPassword), salt);
		case EncoderType.WEB_SAFE_BASE64:
			return authenticate(attemptedPassword, Base64Coder.decodeWebSafe(hashedPassword), salt);

		default:
			return false;
		}
 
	}

	/**
	 * 
	 * @param attemptedPassword
	 * @param encryptedPassword
	 * @param salt
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchProviderException 
	 */
	private boolean authenticate(String attemptedPassword, byte[] encryptedPassword, byte[] salt)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		byte[] encryptedAttemptedPassword = encryptedPassword(attemptedPassword, salt);
		return Arrays.equals(encryptedPassword, encryptedAttemptedPassword);
	}

	/**
	 * 
	 * @param password
	 * @param salt
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchProviderException 
	 */
	public String hashPassword(String password, byte[] salt)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		return hashPassword(password, salt, false);
	}
	
	/**
	 * 
	 * @param password
	 * @param salt
	 * @param inclcudeSalt
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchProviderException
	 */
	public String hashPassword(String password, byte[] salt, boolean inclcudeSalt)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		
		byte[] data = encryptedPassword(password, salt);

		switch (mEncoderType) {
		case EncoderType.HEX:
			return (inclcudeSalt ? HexCoder.toHex(salt) + ":" : "") + HexCoder.toHex(data);

		case EncoderType.WEB_SAFE_BASE64:
			return (inclcudeSalt ? Base64Coder.encodeWebSafe(salt) + ":" : "") + Base64Coder.encodeWebSafe(data);

		default:
			return null;
		}
	}

	/**
	 * 
	 * @param password
	 * @param salt
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchProviderException
	 */
	private byte[] encryptedPassword(String password, byte[] salt)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, mIterations, mDerivedKeyLength);
		SecretKeyFactory f = SecretKeyFactory.getInstance(mKeyFactoryAlgorithm, "BC");
		return f.generateSecret(spec).getEncoded();
	}

	/**  */
	private final int mMinIterations = 0x3E8;
	/**  */
	// http://android-developers.blogspot.com/2013/12/changes-to-secretkeyfactory-api-in.html
	private final String mKeyFactoryAlgorithm = "PBKDF2WithHmacSHA1";
	/**  */
	private final String mSecRandomAlgorithm = "SHA1PRNG";
	// TODO Make this a variable
	/**  */
	private final int mDerivedKeyLength;
	/**  */
	private final int mIterations;

	/**
	 * To get a web safe Base64 encoded <tt>String</tt> use {@link EncoderType#WEB_SAFE_BASE64} value is 1.<br>
	 * To get a HEX encoded <tt>String</tt> use {@link EncoderType#HEX} value is 0
	 */
	public interface EncoderType {
		/** Value 0 */
		final int HEX = 0;
		/** Value 1 */
		final int WEB_SAFE_BASE64 = 1;
	}
	/**  */
	private final int mEncoderType;
}