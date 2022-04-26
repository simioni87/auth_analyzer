package com.protect7.authanalyzer.gui.util;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Point;
import java.awt.GraphicsDevice;
import java.awt.GraphicsEnvironment;
import java.awt.GraphicsConfiguration;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.stream.Stream;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ImageIcon;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;

public class HintCheckBox extends JPanel {
	
	private static final long serialVersionUID = -1192483759892519805L;
	private final JCheckBox checkBox;
	private final JDialog dialog = new JDialog();
	private final JLabel textLabel = new JLabel();
	
	public HintCheckBox(String text) {
		checkBox = new JCheckBox(text);
		setup("");
	}
	
	public HintCheckBox(String text, String hint) {
		checkBox = new JCheckBox(text);
		setup(hint);
	}
	
	public HintCheckBox(String text, boolean selected, String hint) {
		checkBox = new JCheckBox(text, selected);
		setup(hint);
	}

	private void setup(String hint) {
		BoxLayout layout = new BoxLayout(this, BoxLayout.X_AXIS);
		setLayout(layout);
		setAlignmentX(JPanel.LEFT_ALIGNMENT);
		add(checkBox);
		add(Box.createRigidArea(new Dimension(5, 0)));
		ImageIcon hintIcon = new ImageIcon(HintCheckBox.class.getClassLoader().getResource("info_icon.png"));
		JLabel iconLabel = new JLabel(hintIcon);
		add(iconLabel);
		dialog.setUndecorated(true); 
		setHint(hint);
		textLabel.setBorder(BorderFactory.createCompoundBorder(new LineBorder(Color.LIGHT_GRAY, 1, true), new EmptyBorder(3, 3, 3, 3)));
		dialog.add(textLabel);
		iconLabel.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseEntered(MouseEvent e) {
				dialog.repaint();
				dialog.pack();
				int xPos = (int)iconLabel.getLocationOnScreen().getX() + iconLabel.getWidth();
				int yPos = (int)iconLabel.getLocationOnScreen().getY() + iconLabel.getHeight();
				dialog.setLocation(new Point(xPos, yPos));
				dialog.setVisible(true);
				// Correct dialog location if it is shown out of screen
				GraphicsDevice[] devices = GraphicsEnvironment.getLocalGraphicsEnvironment().getScreenDevices();
				int leftDisplayBorder = Stream.
						of(devices).
						map(GraphicsDevice::getDefaultConfiguration).
						map(GraphicsConfiguration::getBounds).
						mapToInt(bounds -> bounds.x + bounds.width).
						max().
						orElse(0);
				int rightPoint = (int)dialog.getLocationOnScreen().getX()+dialog.getWidth();
				while (rightPoint > leftDisplayBorder) {
					rightPoint = rightPoint - 10;
					xPos = xPos - 10;
				}
				dialog.setLocation(new Point(xPos, yPos));
			}
			@Override
			public void mouseExited(MouseEvent e) {
				dialog.setVisible(false);
			}
		});
	}
	
	public void setHint(String hint) {
		textLabel.setText(hint);
		textLabel.putClientProperty("html.disable", null);
	}
	
	public void addActionListener(ActionListener l) {
		checkBox.addActionListener(l);
	}
	
	public String getText() {
		return checkBox.getText();
	}
	
	public void setText(String text) {
		checkBox.setText(text);
	}
	
	public boolean isSelected() {
		return checkBox.isSelected();
	}
	
	public void setSelected(boolean selected) {
		checkBox.setSelected(selected);
	}
}
