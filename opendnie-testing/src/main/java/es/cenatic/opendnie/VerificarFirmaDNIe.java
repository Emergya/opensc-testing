package es.cenatic.opendnie;
/**
 * Programa de ejemplo de verificacion de firma electrónica con DNIe
 *
 * Uso: java TestFirmaDNIe <fichero_original> <fichero de firma>
 *
 * Indica si la firma es válida y corresponde al fichero original
 */

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.util.Enumeration;
import java.security.cert.Certificate;

public class VerificarFirmaDNIe {

	/* editar convenientemente */
	public static final String confLinux=
		"name=OpenSC-OpenDNIe\nlibrary=/usr/lib/opensc-pkcs11.so\n";
	public static final String confWindows=
		"name=OpenSC-OpenDNIe\r\nlibrary=C:\\WINDOWS\\system32\\opensc-pkcs11.dll\r\n";
	public static final String confMac=
		"name=OpenSC-OpenDNIe\nlibrary=/usr/local/lib/opensc-pkcs11.so\n";

	public static final String certAlias="CertFirmaDigital";

	KeyStore myKeyStore=null;

	public VerificarFirmaDNIe(String pin) throws Exception {
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

	private boolean verificaFirma(File file,File signature) throws Exception {
		int c=0;
		FileInputStream fis=null;

		/* volcamos a memoria el fichero original*/
		fis=new FileInputStream(file);
		ByteArrayOutputStream file_os=new ByteArrayOutputStream();
		while ( (c=fis.read()) !=-1 ) file_os.write(c);
		fis.close();

		/* volcamos a memoria el fichero de firma */
		fis=new FileInputStream(signature);
		ByteArrayOutputStream sig_os=new ByteArrayOutputStream();
		while ( (c=fis.read()) !=-1 ) sig_os.write(c);
		fis.close();

		/* extraemos la clave publica del certificado */
        Key key = myKeyStore.getCertificate(certAlias).getPublicKey();
        if(!(key instanceof PublicKey))
        	throw new Exception("El certificado incluye una clave publica para firma!!!");

        /* preparamos la operacion de verificacion */
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initVerify((PublicKey) key);
        sig.update(file_os.toByteArray());

        /* verificamos la firma y retornamos el resultado */
        return sig.verify(sig_os.toByteArray());
	}

	public static void main(String [] args) {
		if (args.length!=3) {
			System.err.println("Uso: java TestFirmaDNIe <fichero_original> <fichero_de_firma> <PIN>");
			System.exit(1);
		}

		/* comprobamos el fichero original */
		File original= new File(args[0]);
		if (! original.isFile()) {
			System.err.println("Error: "+args[0]+" no es un nombre de fichero válido");
			System.exit(1);
		}
		/* comprobamos el fichero de firma */
		File firma= new File(args[1]);
		if (! firma.isFile()) {
			System.err.println("Error: "+args[1]+" no es un nombre de fichero válido");
			System.exit(1);
		}
		if (firma.length()!=256) {
			System.err.println("Error: "+args[1]+" no corresponde a un fichero de firma");
			System.exit(1);
		}
		String pin=PinDialog.showPinDialog();
		if (pin==null) {
			System.err.println("Operación cancelada por el usuario");
			System.exit(0);
		}
		try {
			/* inicializacion */
			System.err.println("Inicializacion");
			VerificarFirmaDNIe t=new VerificarFirmaDNIe(pin);

			/* verificacion de la firma */
			System.err.println("Verificacion de la firma");
			boolean result= t.verificaFirma(original,firma);

			/* informe y finalizacion */
			if (result) {
				System.out.println("Verificación de firma correcta");
				System.out.println("Operación completada con éxito");
			} else {
				System.out.println("Verificación de firma fallida");
			}
			System.exit(0);
		} catch( Exception e) {
			System.err.println(e.toString());
			e.printStackTrace();
			System.exit(1);
		}
	}

}

