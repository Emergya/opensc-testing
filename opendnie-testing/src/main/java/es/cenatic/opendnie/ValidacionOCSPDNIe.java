package es.cenatic.opendnie;
/**
 * Programa de ejemplo de validación OCSP de certificados del DNIE
 *
 * Uso: java ValidacionOCSCPDNIe
 *
 * Por cada uno de los certificados de usuario del DNIE,
 * elabora y envia una petición OCSP vara verificar
 * el estado de revocación
 * Imprime el resultado de dicha comprobación
 */

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.util.Enumeration;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.SingleResp;

public class ValidacionOCSPDNIe {

	/* editar convenientemente */
	public static final String confLinux=
		"name=OpenSC-OpenDNIe\nlibrary=/usr/lib/opensc-pkcs11.so\n";
	public static final String confWindows=
		"name=OpenSC-OpenDNIe\r\nlibrary=C:\\WINDOWS\\system32\\opensc-pkcs11.dll\r\n";
	public static final String confMac=
		"name=OpenSC-OpenDNIe\nlibrary=/usr/local/lib/opensc-pkcs11.so\n";

	public static final String certFirma="CertFirmaDigital";
	public static final String certAutenticacion="CertAutenticacion";

	KeyStore myKeyStore=null;

	public ValidacionOCSPDNIe(String pin) throws Exception {
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

   /**
    * Obtención de la CA intermedia asociada al certificado
    */
   private X509Certificate obtenerCertCAIntermedia(X509Certificate cert)
       throws CertificateException, FileNotFoundException, OCSPException {
	   /* En la validación OCSP se tendrá que usar el certificado de la CA subordinada que emitió el certificado */
       String issuerCN = cert.getIssuerX500Principal().getName("CANONICAL");
       CertificateFactory cfIssuer = CertificateFactory.getInstance("X.509");
       X509Certificate certCA = null;
	   if (issuerCN.contains("cn=ac dnie 001"))
           certCA = (X509Certificate) cfIssuer.generateCertificate(this.getClass().getResourceAsStream("certs/ACDNIE001-SHA1.crt"));
       else if (issuerCN.contains("cn=ac dnie 002"))
           certCA = (X509Certificate) cfIssuer.generateCertificate(this.getClass().getResourceAsStream("certs/ACDNIE002-SHA1.crt"));
       else if (issuerCN.contains("cn=ac dnie 003"))
           certCA = (X509Certificate) cfIssuer.generateCertificate(this.getClass().getResourceAsStream("certs/ACDNIE003-SHA1.crt"));
	   return certCA;
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

	/**
	* Envio y recepción de la petición/respuesta OCSP
	*/
	public BasicOCSPResp realizarPeticionYObtenerRespuestaOCSP(X509Certificate userCert,X509Certificate caCert)
       throws OCSPException, MalformedURLException, IOException,
       CertificateException, InterruptedException {

	   /* Carga del proveedor necesario para la petición OCSP  */
       Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

	   /* Se crea un nuveo objeto OCSPReqGenerator para realizar la petición OCSP  */
       OCSPReqGenerator ocspReqGen = new OCSPReqGenerator();
       System.out.println("Nuevo objeto de peticion OCSP creado");

	   /*
	    * Se añaden el certificado de la CA intermedia
	    * y el certificado a verificar (número de serie) a la petición OCSP
	    */
       System.out.println("Añadiendo certificado a verificar");
       CertificateID certid = new CertificateID(CertificateID.HASH_SHA1, caCert, userCert.getSerialNumber());
       ocspReqGen.addRequest(certid);

       /* Generación de la petición OCSP */
       System.out.println("Creando Peticion OCSP");
       OCSPReq ocspReq = ocspReqGen.generate();

       /* Establecimiento de la conexión con el servidor OCSP del DNIe */
       /* Introducir la URL del servidor OCSP del DNIe */
       URL url = new URL("http://ocsp.dnie.es");
       HttpURLConnection con = (HttpURLConnection)url.openConnection();

       /* Indicar las propiedas de la peticion HTTP */
       con.setRequestProperty("Content-Type", "application/ocsp-request");
       con.setRequestProperty("Accept", "application/ocsp-response");
       con.setDoOutput(true);
       OutputStream out = con.getOutputStream();
       DataOutputStream dataOut = new DataOutputStream(new BufferedOutputStream(out));

       System.out.println("Conexion correcta con el servidor OCSP");

       /*Envío de la petición OCSP al servidor OCSP del DNIe  */
       dataOut.write(ocspReq.getEncoded());
       dataOut.flush();
       dataOut.close();
       System.out.println("Peticion OCSP enviada");

       /* Parseo de la respuesta y obtención del estado del certificado retornado por el OCSP  */
       InputStream in = con.getInputStream();
       if (in==null) throw new IOException("In is null");
       BasicOCSPResp basicResp = (BasicOCSPResp)new OCSPResp(in).getResponseObject();
       System.out.println("Respuesta OCSP recibida");

       /* cierre de conexion y limpieza */
       con.disconnect();
       out.close();
       in.close();

       return basicResp;
   }

	/**
	* Chequeo de la respuesta OCSP recibida
	* Estado de los certificados a validar: GOOD, REVOKED o UKNOWN
	*/
	public void CompruebaRespuestaOCSP(BasicOCSPResp basicResp) {

	   for (SingleResp singResp : basicResp.getResponses()) {
	       Object status = singResp.getCertStatus();
	       String serial = Integer.toHexString(singResp.getCertID().getSerialNumber().intValue());
	       if (status instanceof org.bouncycastle.ocsp.UnknownStatus) {
	           System.out.println("Certificado con numero de serie " + serial + " desconocido");
	       } else if (status instanceof org.bouncycastle.ocsp.RevokedStatus) {
	           System.out.println("Certificado con numero de serie " + serial + " revocado");
	       } else
	           System.out.println("Certificado con numero de serie " + serial + " valido");
	   }
   }

   public static void main(String [] args) {
	   String pin=PinDialog.showPinDialog();
	   if (pin==null) {
		   System.err.println("Operación cancelada por el usuario");
		   System.exit(0);
	   }
		try {
			X509Certificate cert;
			X509Certificate caCert;
			BasicOCSPResp respuesta;

			/* inicializacion */
			System.out.println("Inicializacion");
			ValidacionOCSPDNIe t=new ValidacionOCSPDNIe(pin);

			/* seleccionar certificado de autenticacion y su CA intermedia */
			System.out.println("Buscando certificado de Autenticacion");
			cert=t.getCertificate(certAutenticacion);
			caCert=t.obtenerCertCAIntermedia(cert);
			System.out.println("Certificado de Autenticacion encontrado\nNúmero de serie: "+cert.getSerialNumber() );
			respuesta =t.realizarPeticionYObtenerRespuestaOCSP(cert,caCert);
			t.CompruebaRespuestaOCSP(respuesta);

			/* seleccionar certificado de firma y su CA intermedia */
			System.out.println("Buscando certificado de Firma");
			cert=t.getCertificate(certFirma);
			caCert=t.obtenerCertCAIntermedia(cert);
			System.out.println("Certificado de firma encontrado\nNúmero de serie: "+cert.getSerialNumber() );
			respuesta =t.realizarPeticionYObtenerRespuestaOCSP(cert,caCert);
			t.CompruebaRespuestaOCSP(respuesta);

			/* informe y finalizacion */
			System.out.println("Operacion completada con éxito");
		} catch( Exception e) {
			System.err.println(e.toString());
			e.printStackTrace();
			System.exit(1);
		}
	}

}

