package no.posten.dpost;

import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jcajce.provider.symmetric.DES;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OutputEncryptor;

import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;

public class EncryptAndDecrypt {

	private static final String WORK_DIR = "/Users/gk/digipost/cms-decrypt-example";

	private static final File SOURCE_PDF = new File(WORK_DIR, "source.pdf");
	private static final File DESTINATION_FILE = new File(WORK_DIR, "encrypted.pdf");
	private static final File DECRYPTED_FILE = new File(WORK_DIR, "decrypted.pdf");

	public static void main(final String[] args) throws Exception {
		if (!new File(WORK_DIR).exists()) {
			throw new RuntimeException("Update WORK_DIR to point to the directory the project is cloned into.");
		}
		Files.deleteIfExists(DESTINATION_FILE.toPath());
		Files.deleteIfExists(DECRYPTED_FILE.toPath());

		Security.addProvider(new BouncyCastleProvider());

		X509Certificate certificate = getX509Certificate(new File(WORK_DIR, "certificate.pem"));
		PrivateKey privateKey = getPrivateKey(new File(WORK_DIR, "certificate.p12"), "Qwer12345");

		encrypt(certificate, SOURCE_PDF, DESTINATION_FILE);
		decrypt(privateKey, DESTINATION_FILE, DECRYPTED_FILE);
	}

	private static void decrypt(PrivateKey privateKey, File encrypted, File decryptedDestination) throws IOException, CMSException {
		byte[] encryptedData = Files.readAllBytes(encrypted.toPath());

		CMSEnvelopedDataParser parser = new CMSEnvelopedDataParser(encryptedData);

		RecipientInformation recInfo = getSingleRecipient(parser);
		Recipient recipient = new JceKeyTransEnvelopedRecipient(privateKey);

		try (InputStream decryptedStream = recInfo.getContentStream(recipient).getContentStream()) {
			Files.copy(decryptedStream, decryptedDestination.toPath());
		}

		System.out.println(String.format("Decrypted '%s' to '%s'", encrypted.getAbsolutePath(), decryptedDestination.getAbsolutePath()));
	}

	private static void encrypt(X509Certificate cert, File source, File destination) throws CertificateEncodingException, CMSException, IOException {
		CMSEnvelopedDataStreamGenerator gen = new CMSEnvelopedDataStreamGenerator();
		gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(cert));
		OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).setProvider(BouncyCastleProvider.PROVIDER_NAME).build();

		try (FileOutputStream fileStream = new FileOutputStream(destination);
			 OutputStream encryptingStream = gen.open(fileStream, encryptor)) {

			byte[] unencryptedContent = Files.readAllBytes(source.toPath());
			encryptingStream.write(unencryptedContent);
		}

		System.out.println(String.format("Encrypted '%s' to '%s'", source.getAbsolutePath(), destination.getAbsolutePath()));
	}

	private static X509Certificate getX509Certificate(File certificate) throws IOException, CertificateException {
		try (InputStream inStream = new FileInputStream(certificate)) {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			return (X509Certificate) cf.generateCertificate(inStream);
		}
	}

	private static PrivateKey getPrivateKey(File file, String password) throws Exception {
		KeyStore ks = KeyStore.getInstance("PKCS12");
		try (FileInputStream fis = new FileInputStream(file)) {
			ks.load(fis, password.toCharArray());
		}

		Enumeration<String> aliases = ks.aliases();
		String alias = aliases.nextElement();
		return (PrivateKey) ks.getKey(alias, password.toCharArray());
	}

	private static RecipientInformation getSingleRecipient(CMSEnvelopedDataParser parser) {
		Collection recInfos = parser.getRecipientInfos().getRecipients();
		Iterator recipientIterator = recInfos.iterator();
		if (!recipientIterator.hasNext()) {
			throw new RuntimeException("Could not find recipient");
		}
		return (RecipientInformation) recipientIterator.next();
	}
}
