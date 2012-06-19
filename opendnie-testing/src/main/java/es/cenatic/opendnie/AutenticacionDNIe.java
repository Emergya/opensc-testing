package es.cenatic.opendnie;
/**
 * Programa de ejemplo de autenticacion de usuario DNIe
 *
 * Uso: java AutenticacionDNIe
 *
 * En caso de error indica mensaje apropiado
 * En caso de exito indica el nombre y apellidos del propietario
 * del DNIe
 */

import java.io.ByteArrayInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.util.Enumeration;
import java.security.cert.Certificate;

import java.security.cert.X509Certificate;

public class AutenticacionDNIe {

	/* editar convenientemente */
	public static final String confLinux=
		"name=OpenSC-OpenDNIe\nlibrary=/usr/lib/opensc-pkcs11.so\n";
	public static final String confWindows=
		"name=OpenSC-OpenDNIe\r\nlibrary=C:\\WINDOWS\\system32\\opensc-pkcs11.dll\r\n";
	public static final String confMac=
		"name=OpenSC-OpenDNIe\nlibrary=/usr/local/lib/opensc-pkcs11.so\n";

	public static final String certAlias="CertAutenticacion";

	KeyStore myKeyStore=null;

	public AutenticacionDNIe(String pin) throws Exception {
		/* Creamos el provider PKCS#11 */
		String config="";
		String osName = System.getProperty("os.name").toLowerCase();
		if     (osName.startsWith("win")) config = confWindows;
		else if(osName.startsWith("lin")) config = confLinux;
		else if(osName.startsWith("mac")) config = confMac;

		Provider p = new sun.security.pkcs11.SunPKCS11(
				new ByteArrayInputStream(config.getBytes())
				);
		Security.addProvider(p);

		/* Creamos el keyStore y lo inicializamos con el PIN */
		myKeyStore = KeyStore.getInstance("PKCS11",p);
        char[] pinData = pin.toCharArray();
        myKeyStore.load(null, pinData);

        /* Buscamos el certificado de firma en la lista de certificados */
        Certificate myCert=null;
        for (Enumeration<String> e = myKeyStore.aliases();e.hasMoreElements();) {
        	String alias=e.nextElement();
        	if (alias.equals(certAlias)) myCert=myKeyStore.getCertificate(alias);
        }
        if (myCert==null) throw new Exception("Certificado de autenticacion no encontrado");
	}

	String doAutenticacion(String pin) throws Exception {

		/* FASE 1: verificación de los datos del certificado */
		System.out.println("Comprobando certificado de autenticacion...");

		Certificate cert=myKeyStore.getCertificate(certAlias);
        if (! (cert instanceof X509Certificate) )
        	throw new Exception("Los datos no corresponden a un certificado X509!!");
		X509Certificate x509 = (X509Certificate) cert;
		x509.checkValidity(); // throw exception if certificate expired or not yet valid
		boolean flags [] = x509.getKeyUsage();
		if (!flags[0]) // check digitalSignature usage flag
			throw new Exception("El certificado no es válido para autenticación");

		/* FASE 2: creación de un reto (challenge) para verificacion de claves */
		System.out.println("Generando reto para validación de claves...");

		byte [] challenge = new byte[8];
		for (int n=0;n<8;n++) challenge[n]=new Double(256.0*Math.random()).byteValue();

		/* FASE 3: firma del reto */
		System.out.println("Firmando el reto....");

		/* Extraemos la referencia a la clave privada del certificado */
        Key prkey = myKeyStore.getKey(certAlias, pin.toCharArray());
        if(!(prkey instanceof PrivateKey))
        	throw new Exception("El certificado no tiene asociada una clave privada");

        /* preparamos y ejecutamos la operacion de firma */
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initSign((PrivateKey)prkey);
        sig.update(challenge);
        byte signature [] = sig.sign();

        /* FASE 4: verificacion de la firma */
        System.out.println("Comprobando la firma....");

        /* verificamos la firma realizada */
        sig = Signature.getInstance("SHA1withRSA"); // create a new signature instance for verify
        sig.initVerify(cert);
        sig.update(challenge);
        boolean result = sig.verify(signature);
        if (!result)
        	throw new Exception("No se ha podido verificar la clave pública del certificado");

        /* FASE 5: extracción del nombre de usuario */
        System.out.println("Extrayendo datos del certificado...");
        return x509.toString();
	}

	public static void main(String [] args) {
		String pin=PinDialog.showPinDialog();
		if (pin==null) {
			System.err.println("Operación cancelada por el usuario");
			System.exit(1);
		}
		if (pin.length()<4 || pin.length()>8) {
			System.err.println("El argumento no es un PIN válido");
			System.exit(2);
		}
		try {
			/* inicializacion */
			System.out.println("Inicializacion");
			AutenticacionDNIe t=new AutenticacionDNIe(pin);

			/* firma */
			System.out.println("Autenticacion");
			String result= t.doAutenticacion(pin);

			/* informe y finalizacion */
			if (result!=null) {
				System.out.println("Operacion completada con éxito");
				System.out.println("Certificado: \n"+result);
			} else {
				System.err.println("Verificación del certificado fallida");
			}
			System.exit(0);
		} catch( Exception e) {
			System.err.println(e.toString());
			e.printStackTrace();
			System.exit(1);
		}
	}

}

