/* 
 * PinDialog.java Copyright (C) 2012 This file is part of OpenSC project
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

import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;

/**
 * Simple PIN dialog 
 * 
 * @author adiaz
 *
 */
public class PinDialog {
	
	//TODO: i18n

	public static String showPinDialog() {
		JPasswordField jpf = new JPasswordField(8);
		JPanel p=new JPanel();
		p.setLayout(new BoxLayout(p,BoxLayout.Y_AXIS));
		p.add(new JLabel("Insert card in smartcard reader"));
		p.add(new JLabel("Insert PIN code:"));
		p.add(new JLabel(" "));
		p.add(jpf);
		int res= JOptionPane.showConfirmDialog(
				null,
				p,
				"PIN request",
				JOptionPane.OK_CANCEL_OPTION,
				JOptionPane.QUESTION_MESSAGE);
		if (res==JOptionPane.OK_OPTION) return new String(jpf.getPassword());
		return null;
	}

}
