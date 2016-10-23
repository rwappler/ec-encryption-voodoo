package com.valtech.de.ecencryption

import java.io.File
import java.io.FileOutputStream
import java.io.FileReader
import java.io.FileWriter
import java.nio.file.Files
import java.nio.file.Paths
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Security
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.openssl.jcajce.JcaPEMWriter

import javax.crypto.Cipher

object EcEncryptor {

	val encryptionAlgorithm = "ECIES"
	val ecCurve = "secp192k1"
	val signatureAlgorithm = "SHA256withECDSA"
	
	/* Note: If you extend scala.App, this code will not be executed immediately
   * due to the inherited DelayedInit trait. As a result, BC will not be available.
   */
	Security.addProvider(new BouncyCastleProvider)

	private type OptionMap = Map[String, Any]

	def nextOption(opts: OptionMap, optList: List[String]): Map[String, Any] = {
		optList match {
			case Nil => opts
			case "generateKeyPair" :: tail => nextOption(opts + ("command" -> "generateKeyPair"), tail)
			case "sign" :: tail => nextOption(opts + ("command" -> "sign"), tail);
			case "verify" :: tail => nextOption(opts + ("command" -> "verify"), tail)
			case "encrypt" :: tail => nextOption(opts + ("command" -> "encrypt"), tail)
			case "--keyFile" :: fileName :: tail => nextOption(opts + ("keyFile" -> new File(fileName)), tail)
			case "--signature" :: fileName :: tail => nextOption(opts + ("signature" -> new File(fileName)), tail)
			case "--data" :: fileName :: tail => nextOption(opts + ("data" -> new File(fileName)), tail);
			case "--out" :: fileName :: tail => nextOption(opts + ("out" -> new File(fileName)), tail);
			case trash :: tail => throw new IllegalArgumentException("Unknown option: `" + trash + "'");
		}
	}

	def processCommand(opts: OptionMap): Unit = {
		def readAndClose(f: File): Array[Byte] =
			Files.readAllBytes(Paths.get(f.getAbsolutePath))

		def readKeyFile(f: File): KeyPair = {
			val parser = new PEMParser(new FileReader(f));
			val key = parser.readObject()
			parser.close();

			new JcaPEMKeyConverter().getKeyPair(key.asInstanceOf[PEMKeyPair])
		}

		opts("command") match {
			case "generateKeyPair" =>
				val keyPair = generateKeyPair();
				val writer = new JcaPEMWriter(new FileWriter(opts("keyFile").asInstanceOf[File]))
				writer.writeObject(keyPair)
				writer.flush();
				writer.close();

			case "verify" =>
				val (data, pubKey, signature) = (
					readAndClose(opts("data").asInstanceOf[File]),
					readKeyFile(opts("keyFile").asInstanceOf[File]).getPublic,
					Base64.getDecoder.decode(readAndClose(opts("signature").asInstanceOf[File])))

				if (verify(pubKey, data, signature))
					println("Ok")
				else println("Invalid")

			case "sign" =>
				val (data, privKey, signature) = (
					readAndClose(opts("data").asInstanceOf[File]),
					readKeyFile(opts("keyFile").asInstanceOf[File]).getPrivate,
					Base64.getEncoder.wrap(new FileOutputStream(opts("signature").asInstanceOf[File])))
				sign(privKey, data).foreach { signature.write(_) }
				signature.flush()
				signature.close()

			case "encrypt" =>
				val (data, keyPair, output) = (
					readAndClose(opts("data").asInstanceOf[File]),
					readKeyFile(opts("keyFile").asInstanceOf[File]),
					Base64.getEncoder.wrap(new FileOutputStream(opts("out").asInstanceOf[File])))

				encrypt(keyPair.getPublic, data).foreach { output.write(_) }
				output.flush()
				output.close()

			case x => throw new Error("Not yet implemented: " + x)
		}
	}

	def encrypt(publicKey: PublicKey, data: Array[Byte]): Array[Byte] = {
		val cipher = Cipher.getInstance(encryptionAlgorithm)
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		cipher.doFinal(data);
	}

	def generateKeyPair(): KeyPair = {
		/*
     * It is important to use BC here, otherwise you will get:
     * [info]   org.bouncycastle.openssl.PEMException: problem creating EC private key: java.lang.NullPointerException
		 * [info]   at org.bouncycastle.openssl.PEMParser$KeyPairParser.parseObject(Unknown Source)
		 * [info]   at org.bouncycastle.openssl.PEMParser.readObject(Unknown Source)
     */
		val kpg = KeyPairGenerator.getInstance("EC", "BC");
		val ecParams = new ECGenParameterSpec(ecCurve);

		kpg.initialize(ecParams);
		kpg.generateKeyPair();
	}

	def sign(privateKey: PrivateKey, bytes: Array[Byte]): Array[Byte] = {
		val signer = Signature.getInstance(signatureAlgorithm)
		signer.initSign(privateKey);
		signer.update(bytes);
		signer.sign();
	}

	def verify(publicKey: PublicKey, bytes: Array[Byte], signature: Array[Byte]): Boolean = {
		val signer = Signature.getInstance(signatureAlgorithm);
		signer.initVerify(publicKey)
		signer.update(bytes)
		signer.verify(signature);
	}

	def main(args: Array[String]) = {
		processCommand(nextOption(Map(), args.toList))
	}

	def decrypt(keyPair: KeyPair, cipherText: Array[Byte]) = {
		val decryptor = Cipher.getInstance(encryptionAlgorithm);

		decryptor.init(Cipher.DECRYPT_MODE, keyPair.getPrivate)
		decryptor.doFinal(cipherText);
	}
}