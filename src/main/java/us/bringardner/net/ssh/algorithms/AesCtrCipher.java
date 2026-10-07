/**
 * <PRE>
 * 
 * Copyright Tony Bringardner 1998, 2026 <A href="http://bringardner.com/tony">Tony Bringardner</A>
 * 
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       <A href="http://www.apache.org/licenses/LICENSE-2.0">http://www.apache.org/licenses/LICENSE-2.0</A>
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *  </PRE>
 *   
 *   
 *	@author Tony Bringardner   
 *
 *
 * ~version~V000.00.01-V000.00.00-
 */
package us.bringardner.net.ssh.algorithms;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * aes128-ctr, aes192-ctr and aes256-ctr (RFC 4344), used with a MAC.
 *
 * @author Tony Bringardner
 */
public class AesCtrCipher implements ISshCipher {

	private final String name;
	private final int keySize;
	private Cipher cipher;

	public AesCtrCipher(String name, int keySize) {
		this.name = name;
		this.keySize = keySize;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public int getKeySize() {
		return keySize;
	}

	@Override
	public int getIvSize() {
		return 16;
	}

	@Override
	public int getBlockSize() {
		return 16;
	}

	@Override
	public void init(boolean encrypt, byte[] key, byte[] iv) throws GeneralSecurityException {
		Cipher tmp = Cipher.getInstance("AES/CTR/NoPadding");
		tmp.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, new SecretKeySpec(key, 0, keySize, "AES"), new IvParameterSpec(iv, 0, 16));
		cipher = tmp;
	}

	@Override
	public void update(byte[] buf, int off, int len) throws GeneralSecurityException {
		if( len > 0 ) {
			int n = cipher.update(buf, off, len, buf, off);
			if( n != len ) {
				throw new GeneralSecurityException("AES-CTR returned "+n+" of "+len+" bytes");
			}
		}
	}
}
