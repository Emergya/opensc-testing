package es.cenatic.opendnie;
/**
 * Programa de ejemplo de firma electrónica con DNIe
 *
 * Uso: java TestFirmaDNIe <fichero_afirmar>
 *
 * En caso de error indica mensaje apropiado
 * En caso de exito guarda la firma en el fichero "<fichero_a_firmar>.sign"
 */

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.util.Enumeration;
import java.security.cert.Certificate;

public class TestFirmaDNIe {

	/* editar convenientemente */
	public static final String confLinux=
		"name=OpenSC-OpenDNIe\nlibrary=/usr/lib/opensc-pkcs11.so\n";
	public static final String confWindows=
		"name=OpenSC-OpenDNIe\r\nlibrary=C:\\WINDOWS\\system32\\opensc-pkcs11.dll\r\n";
	public static final String confMac=
		"name=OpenSC-OpenDNIe\nlibrary=/usr/local/lib/opensc-pkcs11.so\n";

	public static final String certAlias="CertFirmaDigital";

	KeyStore myKeyStore=null;

	public TestFirmaDNIe(String pin) throws Exception {
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
        if (myCert==null) throw new Exception("Certificado de firma no encontrado");
	}

	public byte [] doFirma(File f,String pin) throws Exception {
		int c;

		/* volcamos a memoria el fichero */
		FileInputStream fis=new FileInputStream(f);
		ByteArrayOutputStream baos=new ByteArrayOutputStream();
		while ( (c=fis.read()) !=-1 ) baos.write(c);
		fis.close();

		/* extraemos la clave del certificado */
        Key key = myKeyStore.getKey(certAlias, pin.toCharArray());
        if(!(key instanceof PrivateKey))
        	throw new Exception("El certificado no tiene asociada una clave privada");

        /* preparamos la operacion de firma */
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initSign((PrivateKey)key);
        sig.update(baos.toByteArray());

        /* firmamos los datos y retornamos el resultado */
        return sig.sign();
	}

	public static void main(String [] args) {
		if (args.length!=1) {
			System.err.println("Uso: java TestFirmaDNIe <fichero_a_firmar>");
			System.exit(1);
		}
		File f= new File(args[0]);
		if (! f.isFile()) {
			System.err.println("Error: "+args[0]+" no es un nombre de fichero válido");
			System.exit(2);
		}
		String pin=PinDialog.showPinDialog();
		if (pin==null) {
			System.err.println("Operación cancelada por el usuario");
			System.exit(2);
		}
		try {
			/* inicializacion */
			System.out.println("Inicializacion");
			TestFirmaDNIe t=new TestFirmaDNIe(pin);

			/* firma */
			System.out.println("Operacion de firma");
			byte [] result= t.doFirma(f,pin);

			/* almacenamiento del resultado */
			System.out.println("Guardando el resultado");
			File out= new File(args[0]+".sign");
			FileOutputStream fos =new FileOutputStream (out);
			for (int n=0; n<result.length;n++) fos.write(result[n]);
			fos.close();

			/* informe y finalizacion */
			System.out.println("Operacion completada con éxito");
			System.out.println("Firma guardada en: "+args[0]+".sign");
			System.exit(0);
		} catch( Exception e) {
			System.err.println(e.toString());
			e.printStackTrace();
			System.exit(1);
		}
	}

}

