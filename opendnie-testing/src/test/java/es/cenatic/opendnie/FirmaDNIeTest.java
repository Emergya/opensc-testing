package es.cenatic.opendnie;
/**
 * Programa de ejemplo de firma electrónica con DNIe
 *
 * Uso: java TestFirmaDNIe <fichero_afirmar>
 *
 * En caso de error indica mensaje apropiado
 * En caso de exito guarda la firma en el fichero "<fichero_a_firmar>.sign"
 */


import java.io.File;
import java.io.FileOutputStream;

import org.junit.Test;

public class FirmaDNIeTest {

	/* editar convenientemente */
	public static final String confLinux=
		"name=OpenSC-OpenDNIe\nlibrary=/usr/lib/opensc-pkcs11.so\n";
	public static final String confWindows=
		"name=OpenSC-OpenDNIe\r\nlibrary=C:\\WINDOWS\\system32\\opensc-pkcs11.dll\r\n";
	public static final String confMac=
		"name=OpenSC-OpenDNIe\nlibrary=/usr/local/lib/opensc-pkcs11.so\n";
	
	private static String fileToSign = "src/test/resources/fileToSign.pdf";

	public static final String certAlias="CertFirmaDigital";

	@Test
	public void testFirmaDNIe() {
		File f= new File(fileToSign);
		if (! f.isFile()) {
			System.err.println("Error: "+fileToSign+" no es un nombre de fichero válido");
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
			File out= new File(fileToSign+".sign");
			FileOutputStream fos =new FileOutputStream (out);
			for (int n=0; n<result.length;n++) fos.write(result[n]);
			fos.close();

			/* informe y finalizacion */
			System.out.println("Operacion completada con éxito");
			System.out.println("Firma guardada en: "+fileToSign+".sign");
			System.exit(0);
		} catch( Exception e) {
			System.err.println(e.toString());
			e.printStackTrace();
			System.exit(1);
		}
	}

}

