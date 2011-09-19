package es.cenatic.opendnie;
/**
 * Programa de ejemplo de seleccion de certificados con el DNIe
 *
 * Uso: java MostrarCertificadoDNIe
 *
 * Busca e imprime los números de serie de los certificados de
 * autenticación y firma del DNIe
 */

import java.security.cert.X509Certificate;

import org.junit.Test;

public class MostrarCertificadosDNIeTest {

	@Test
	public void testMostrarCertificadosDNIe() {

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
			cert=t.getCertificate(t.certAutenticacion);
			System.out.println("Certificado de Autenticacion encontrado\nNúmero de serie: "+cert.getSerialNumber() );

			/* seleccionar certificado de firma */
			System.out.println("Buscando certificado de Firma");
			cert=t.getCertificate(t.certFirma);
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
