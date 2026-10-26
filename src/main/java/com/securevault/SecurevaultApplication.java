package com.securevault;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

import java.security.Security;

@SpringBootApplication
@ConfigurationPropertiesScan
public class SecurevaultApplication {

	static {
		// Enregistre Bouncy Castle comme provider crypto JCA
		// Fait en static initializer pour garantir la disponibilité avant tout démarrage
		if(Security.getProvider("BC") == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	public static void main(String[] args) {
		SpringApplication.run(SecurevaultApplication.class, args);
	}

}
