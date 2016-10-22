package com.valtech.de.ecencryption

import org.scalatest.FlatSpec
import java.security.SecureRandom
import java.security.KeyPair
import java.security.SignatureException

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
    return (kp, bytes, signature)
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
  
}