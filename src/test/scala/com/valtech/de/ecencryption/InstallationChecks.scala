package com.valtech.de.ecencryption

import org.scalatest.FlatSpec
import java.security.KeyPairGenerator
import org.scalatest.Matchers
import java.security.spec.ECParameterSpec
import collection.JavaConversions.enumerationAsScalaIterator
import java.util.Enumeration
import java.security.spec.ECGenParameterSpec
import java.io.Writer
import java.io.ByteArrayOutputStream
import java.io.OutputStreamWriter
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.openssl.PEMParser
import java.io.ByteArrayInputStream
import java.io.InputStreamReader
import java.security.KeyPair
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMWriter
import javax.crypto.Cipher
import javax.crypto.spec.PBEKeySpec
import java.security.KeyFactory
import com.sun.crypto.provider.PBEKeyFactory
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEParameterSpec
import java.security.SecureRandom
import java.security.AlgorithmParameters

class InstallationChecks extends FlatSpec with Matchers {

	// Security.addProvider(new BouncyCastleProvider)

	"The JCE provider" should "support EC key generation" in {
		assert(Option(KeyPairGenerator.getInstance("EC")).isDefined);
	}

	/* it should "provide names of ECC curves" in {
     assert(!ECNamedCurveTable.getNames.isEmpty)
     ECNamedCurveTable.getNames.asInstanceOf[Enumeration[String]].foreach(info(_));
  } */

	it should "be able to generate an EC Key Pair" in {
		assert(Option(EcEncryptor.generateKeyPair()).isDefined)
	}

	it can "read EC Key Pairs" in {
		val keyPair = EcEncryptor.generateKeyPair();
		val out = new ByteArrayOutputStream
		val w = new JcaPEMWriter(new OutputStreamWriter(out))
		w.writeObject(keyPair)
		w.flush()
		var r = new PEMParser(new InputStreamReader(new ByteArrayInputStream(out.toByteArray())))
		val readKP = r.readObject();
		r.close
		w.close

		assert(readKP != null);
		assert(readKP.isInstanceOf[PEMKeyPair])
		val converter = new JcaPEMKeyConverter();
		val convertedKP = converter.getKeyPair(readKP.asInstanceOf[PEMKeyPair]);

		assert(keyPair.getPrivate.getFormat == convertedKP.getPrivate.getFormat)
	}

	it should "manage ECIES encryption-decryption round-trip" in {
		val kpg = KeyPairGenerator.getInstance("EC")
		val ecGenParameters = new ECGenParameterSpec("secp192k1")
		kpg.initialize(ecGenParameters)

		val kp = kpg.generateKeyPair()

		val plainBytes = Array[Byte](0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0)

		val encryptor = Cipher.getInstance("ECIES")
		encryptor.init(Cipher.ENCRYPT_MODE, kp.getPublic)
		val cipherBytes = encryptor.doFinal(plainBytes)

		// ------------------------------------------------------------

		val decryptor = Cipher.getInstance("ECIES")
		decryptor.init(Cipher.DECRYPT_MODE, kp.getPrivate)
		val decryptedBytes = decryptor.doFinal(cipherBytes)

		assert(plainBytes.deep == decryptedBytes.deep)
	}

	"The JRE" should "have Unlimited Strength Jurisdiction Policies installed" in {
		val aLongPassword = "Rumors say, the password length without the unlimited strength jurisdiction policy is at most 16 characters"
		val myPayload = "If we can encrypt this sentence, then the policies are probably installed."

		val algorithm = "PBEWithHMACSHA256AndAES_256";
		val maxKeyLength = Cipher.getMaxAllowedKeyLength(algorithm);
		val encrypter = Cipher.getInstance(algorithm)

		val key = SecretKeyFactory.getInstance(encrypter.getAlgorithm).generateSecret(new PBEKeySpec(aLongPassword.toArray))

		info("Max key length for " + algorithm + " is " + maxKeyLength)
		assert(maxKeyLength > 128)

		encrypter.init(Cipher.ENCRYPT_MODE, key);
		val cipherText = encrypter.doFinal(myPayload.toCharArray().map(_.toByte))
		val algParams = encrypter.getParameters;

		val decryptor = Cipher.getInstance(algorithm);
		decryptor.init(Cipher.DECRYPT_MODE, key, algParams);
		val plainBytes = decryptor.doFinal(cipherText);

		val plainText = plainBytes.foldLeft(StringBuilder.newBuilder)((builder, b) => builder.append(b.toChar)).mkString

		assert(myPayload == plainText)

	}
}