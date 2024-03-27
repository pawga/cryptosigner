package com.pawga.cryptosigner.cryptosigner

import com.pawga.cryptosigner.CryptoSignerRsa
import com.pawga.exception.CryptoSignerException
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.File
import kotlin.test.assertFailsWith

/**
 * Created by pawga777 on 14.03.2024
 */
class CryptoSignerRsaTest {
    private val cryptoSignerRsa: CryptoSignerRsa = CryptoSignerRsa()

    @Test
    fun generateKeyPair() {
        cryptoSignerRsa.generateKeyPair()
        printKeyInfos()
    }

    @Test
    fun exportKeyPair() {
        assertFailsWith<CryptoSignerException>(
            message = "No exception found",
            block = {
                cryptoSignerRsa.exportKeyPair("private.key", "public.key")
            }
        )
    }

    @Test
    fun all() {
        cryptoSignerRsa.generateKeyPair()
        cryptoSignerRsa.exportKeyPair("private.key", "public.key")
        cryptoSignerRsa.importKeyPair(File("private.key"), File("public.key"))

        cryptoSignerRsa.encrypt(File("test.txt").inputStream(), File("test.enc").outputStream())
        cryptoSignerRsa.decrypt(File("test.enc").inputStream(), File("test_dec.txt").outputStream())

        cryptoSignerRsa.sign(File("test.txt").inputStream(), File("test.sig").outputStream())
        val result = cryptoSignerRsa.verify(File("test.txt").inputStream(), File("test.sig").inputStream())
        Assertions.assertTrue(result)

        val source = File("test.txt").inputStream().readAllBytes()
        val encrypt = cryptoSignerRsa.encrypt(source)
        val decrypt = cryptoSignerRsa.decrypt(encrypt)
        Assertions.assertTrue(decrypt.contentEquals(source))

        val sig = cryptoSignerRsa.sign(source)
        Assertions.assertTrue(cryptoSignerRsa.verify(source, sig))

        // new KeyPair
        cryptoSignerRsa.generateKeyPair()
        Assertions.assertTrue(!cryptoSignerRsa.verify(source, sig))
        assertFailsWith<Exception>(
            message = "No exception found",
            block = {
                Assertions.assertTrue(!cryptoSignerRsa.decrypt(encrypt).contentEquals(source))
            }
        )

        cryptoSignerRsa.importKeyPair(File("private.key"), File("public.key"))
        Assertions.assertTrue(cryptoSignerRsa.decrypt(encrypt).contentEquals(source))
    }

    private fun printKeyInfos() {
        println("Public Key: " + getHexString(cryptoSignerRsa.getPublicKey().encoded))
        println("Private Key: " + getHexString(cryptoSignerRsa.getPrivateKey().encoded))
    }

    private fun getHexString(b: ByteArray): String {
        val result = StringBuilder()
        for (value in b) {
            result.append(((value.toInt() and 0xff) + 0x100).toString(16).substring(1))
        }
        return result.toString()
    }
}