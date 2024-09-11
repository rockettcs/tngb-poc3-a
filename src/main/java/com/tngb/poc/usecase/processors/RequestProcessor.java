package com.tngb.poc.usecase.processors;

import com.tngb.poc.usecase.utils.Utils;
import org.apache.camel.Exchange;
import org.apache.camel.Processor;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Base64;

@Component
public class RequestProcessor implements Processor {

    private static final Logger logger = LoggerFactory.getLogger(RequestProcessor.class);

    @Override
    public void process(Exchange exchange) throws Exception {
        byte[] inputData = exchange.getIn().getBody(String.class).trim().getBytes();

        String privateKeyPath = exchange.getProperty("privateKeyPath", String.class);
        String privateKeyPassword = exchange.getProperty("privateKeyPassword", String.class);
        String publicKeyPath = exchange.getProperty("publicKeyPath", String.class);

        Key key = Utils.getKey(privateKeyPath, privateKeyPassword);
        Certificate certificate = Utils.getCertificate(privateKeyPath, privateKeyPassword);
        logger.info("Creating Signature with the inputData!!");
        byte[] signature = Utils.generateSignature(inputData, key);
        logger.info("Signature created successfully with the inputData and privateKey!!");
        String encodedOriginalData = Base64.getEncoder().encodeToString(inputData);
        logger.info("OrgContent Encoded Value :: {}", encodedOriginalData);
        String encodedSignature = Base64.getEncoder().encodeToString(signature);
        logger.info("Signature Encoded Value :: {}", encodedSignature);
        String encodedCertificate = Base64.getEncoder().encodeToString(certificate.getEncoded());
        logger.info("Certificate Encoded Value :: {}", encodedCertificate);

        String xmlEnvelope = Utils.createXmlEnvelope(encodedOriginalData, encodedSignature, encodedCertificate);
        logger.info("XmlEnvelope :: {}", xmlEnvelope);

        PublicKey publicKey = Utils.getPublicKey(publicKeyPath);

        PGPPublicKey pgpPublicKey = Utils.getPGPPublicKey(publicKey);
        logger.info("Sending XmlEnvelope for PGP Encryption!!");
        String pgpEncryptedData = Utils.encryptDataWithPGP(pgpPublicKey, xmlEnvelope.getBytes());
        logger.info("PGP Encrypted Request :: {}", pgpEncryptedData);
        exchange.getIn().setBody(pgpEncryptedData);
    }

}
