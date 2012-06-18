/* 
 * ListCertificatesTest.java Copyright (C) 2012 This file is part of OpenSC project
 * 
 * This software is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * As a special exception, if you link this library with other files to
 * produce an executable, this library does not by itself cause the
 * resulting executable to be covered by the GNU General Public License.
 * This exception does not however invalidate any other reasons why the
 * executable file might be covered by the GNU General Public License.
 * 
 * Authors:: Alejandro Díaz Torres (mailto:adiaz@emergya.com)
 * Authors:: Alejandro Díaz Torres (mailto:aledt84@gmail.com)
 */
package org.opensc.testing;

import java.io.IOException;

import org.junit.Assert;
import org.junit.Test;

/**
 * This JUnit test list smartcard certificates in a smartcard using opensc
 * 
 * @author adiaz
 *
 */
public class ListCertificatesTest extends OpenSCTestBase{

	@Test
	public void testAnyCertificate() throws IOException { 
		try {
			verbose = true;
			/* sc init */
			init();
			Assert.assertTrue(numCertificates>0);
		} catch( Exception e) {
			System.err.println(e.toString());
			e.printStackTrace();
			Assert.fail();
		}
	}

}

