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

  "The JCE provider" can "read EC Key Pairs" in {
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
}