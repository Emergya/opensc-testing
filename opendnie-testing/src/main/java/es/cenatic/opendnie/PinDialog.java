package es.cenatic.opendnie;

import javax.swing.BoxLayout;
import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;

public class PinDialog {
    public static final ImageIcon icon=
    	new ImageIcon(PinDialog.class.getResource("/icons/dnie_logo.jpg"));

	public static String showPinDialog() {
		JPasswordField jpf = new JPasswordField(8);
		JPanel p=new JPanel();
		p.setLayout(new BoxLayout(p,BoxLayout.Y_AXIS));
		p.add(new JLabel("Inserte el DNIe en el lector"));
		p.add(new JLabel("Introduzca el código PIN:"));
		p.add(new JLabel(" "));
		p.add(jpf);
		int res= JOptionPane.showConfirmDialog(
				null,
				p,
				"Petición de PIN",
				JOptionPane.OK_CANCEL_OPTION,
				JOptionPane.QUESTION_MESSAGE,
				icon);
		if (res==JOptionPane.OK_OPTION) return new String(jpf.getPassword());
		return null;
	}

}
