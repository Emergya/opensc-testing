package es.cenatic.opendnie;
/**
 * Programa de ejemplo de seleccion de certificados con el DNIe
 *
 * Uso: java MostrarCertificadoDNIe
 *
 * Busca e imprime los números de serie de los certificados de
 * autenticación y firma del DNIe
 */

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.util.Enumeration;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class MostrarCertificadosDNIe {

	/* editar convenientemente */
	public static final String confLinux=
		"name=OpenSC-OpenDNIe\nlibrary=/usr/lib/opensc-pkcs11.so\n";
	public static final String confWindows=
		"name=OpenSC-OpenDNIe\r\nlibrary=C:\\WINDOWS\\system32\\opensc-pkcs11.dll\r\n";
	public static final String confMac=
		"name=OpenSC-OpenDNIe\nlibrary=/usr/local/lib/opensc-pkcs11.so\n";

	public static final String certFirma="CertFirmaDigital";
	public static final String certAutenticacion="CertAutenticacion";
	public static final String certCAIntermedia="CertCAIntermediaDGP";

	KeyStore myKeyStore=null;

	public MostrarCertificadosDNIe(String pin) throws Exception {
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
	}

	public X509Certificate getCertificate(String certAlias) throws Exception {
        /* Buscamos el certificado de firma en la lista de certificados */
        Certificate myCert=null;
        for (Enumeration<String> e = myKeyStore.aliases();e.hasMoreElements();) {
        	String alias=e.nextElement();
        	if (alias.equals(certAlias)) myCert=myKeyStore.getCertificate(alias);
        }
        if (myCert==null) throw new Exception("Certificado con alias '"+certAlias+"' no encontrado");
        if (!(myCert instanceof X509Certificate))
        	throw new Exception("El certificado no es de tipo X509!!!");
        return (X509Certificate) myCert;
	}

	public static void main(String [] args) {

		/* pedimos contraseña al usuario */
		String pin=PinDialog.showPinDialog();
		if (pin==null) {
			System.err.println("Operacion cancelada por el usuario");
			System.exit(0);
		}

		try {
			X509Certificate cert;

			/* inicializacion */
			System.out.println("Inicializacion");
			MostrarCertificadosDNIe t=new MostrarCertificadosDNIe(pin);

			/* seleccionar certificado de autenticacion */
			System.out.println("Buscando certificado de Autenticacion");
			cert=t.getCertificate(certAutenticacion);
			System.out.println("Certificado de Autenticacion encontrado\nNúmero de serie: "+cert.getSerialNumber() );

			/* seleccionar certificado de firma */
			System.out.println("Buscando certificado de Firma");
			cert=t.getCertificate(certFirma);
			System.out.println("Certificado de firma encontrado\nNúmero de serie: "+cert.getSerialNumber() );

			/* informe y finalizacion */
			System.out.println("Operacion completada con éxito");
		} catch( Exception e) {
			System.err.println(e.toString());
			e.printStackTrace();
			System.exit(1);
		}
	}

}

