package com.valtech.de.ecencryption

import org.scalatest.FlatSpec
import java.security.SecureRandom
import java.security.KeyPair
import java.security.SignatureException
import java.security.KeyPairGenerator
import org.bouncycastle.crypto.params.ECKeyGenerationParameters
import org.bouncycastle.crypto.params.ECDomainParameters
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher

class EncryptorTests extends FlatSpec {
  
  "The encryptor" should "generate key pairs" in {
    val kp = EcEncryptor.generateKeyPair()
    assert(Option(kp).isDefined)
    assert(kp.getPrivate != None)
    assert(kp.getPublic != None)
  }
  
  it should "generate message digests" in {
    val signature = makeSignature()._3;
    assert(Option(signature).isDefined);
    assert(signature.length > 0)
  }

  def makeSignature() : (KeyPair, Array[Byte], Array[Byte]) = {
    val kp = EcEncryptor.generateKeyPair();
    val bytes = Array.fill[Byte](10)(20);
    val signature = EcEncryptor.sign(kp.getPrivate, bytes);
    (kp, bytes, signature)
  }
  
  def makeEncryption() : (KeyPair, Array[Byte], Array[Byte]) = {
  	val kp = EcEncryptor.generateKeyPair()
  	val plainText = Array.fill[Byte](10)(0x0F)
  	val cipherText = EcEncryptor.encrypt(kp.getPublic, plainText)
  	(kp, plainText, cipherText)
  }
  it should "verify signatures" in {
    val (kp, bytes, signature) = makeSignature();
    assert(EcEncryptor.verify(kp.getPublic, bytes, signature));
  }
  
  it should "detect invalid signatures" in {
    val (kp, bytes, signature) = makeSignature();
    signature(4) = (~signature(4)).toByte
    assert(!EcEncryptor.verify(kp.getPublic, bytes, signature))
  }
  
  it should "detect a signature from the wrong key" in {
    val (_, bytes, signature) = makeSignature();
    val wrongKp = EcEncryptor.generateKeyPair();
    
    assert(!EcEncryptor.verify(wrongKp.getPublic, bytes, signature));
  }
  
  it should "detect tampered payload" in {
  	val (keyPair, bytes, signature) = makeSignature()
  	val tamperedPayload = bytes.clone()
  	tamperedPayload(4) = (~tamperedPayload(4)).toByte
  	
  	assert(!EcEncryptor.verify(keyPair.getPublic, tamperedPayload, signature))
  }
  
  it should "decrypt payload with the correct key" in {
  	val (kp, plainText, cipherText) = makeEncryption();
  	
  	assert(EcEncryptor.decrypt(kp.getPrivate, cipherText).deep == plainText.deep)
  }
   
}