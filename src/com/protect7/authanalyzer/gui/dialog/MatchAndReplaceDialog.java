package com.protect7.authanalyzer.gui.dialog;

import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ArrayList;
import java.util.Iterator;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.WindowConstants;
import javax.swing.border.EmptyBorder;
import com.protect7.authanalyzer.entities.MatchAndReplace;
import com.protect7.authanalyzer.gui.entity.SessionPanel;
import com.protect7.authanalyzer.gui.util.PlaceholderTextField;

public class MatchAndReplaceDialog extends JDialog {

	private static final long serialVersionUID = 7866009243313757748L;
	private final int TEXTFIELD_WIDH = 25;
	private final JPanel listPanel = (JPanel) getContentPane();
	private final GridBagConstraints c = new GridBagConstraints();
	private final ArrayList<MatchAndReplace> matchAndReplaceList;
	private final String INFO_TEXT;
	private final PlaceholderTextField matchInputText = new PlaceholderTextField(TEXTFIELD_WIDH);
	private final PlaceholderTextField replaceInputText = new PlaceholderTextField(TEXTFIELD_WIDH);
	private final JButton addEntryButton = new JButton("\u2795");
	private final JButton okButton = new JButton("OK");
	
	public MatchAndReplaceDialog(SessionPanel sessionPanel) {
		matchAndReplaceList = sessionPanel.getMatchAndReplaceList();
		INFO_TEXT = "Specify Match and Replace rules (string literals) for all repeated requests of the session \""+sessionPanel.getSessionName()+"\"";
		listPanel.setLayout(new GridBagLayout());
		listPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

		addEntryButton.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				addMatchAndReplace(matchInputText.getText(), replaceInputText.getText());
				updateMatchAndReplaceList();
				SwingUtilities.getWindowAncestor((Component) e.getSource()).pack();
			}
		});
		updateMatchAndReplaceList();
		setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);	
		setVisible(true);
		setTitle("Match and Replace for Session " + sessionPanel.getSessionName());
		pack();
		setLocationRelativeTo(sessionPanel);
		
		okButton.addActionListener(e -> {
			addMatchAndReplace(matchInputText.getText(), replaceInputText.getText());
			dispose();
		});
			
		addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosed(WindowEvent e) {
				sessionPanel.updateMatchAndReplaceButtonText();
			}
		});
	}

	private void updateMatchAndReplaceList() {
		listPanel.removeAll();
		c.fill = GridBagConstraints.HORIZONTAL;
		c.insets = new Insets(0, 5, 20, 0);
		c.gridx = 0;
		c.gridy = 0;
		c.gridwidth = 3;
		listPanel.add(new JLabel(INFO_TEXT), c);
		c.insets = new Insets(0, 5, 5, 0);
		c.gridwidth = 1;
		c.gridy++;
		listPanel.add(new JLabel("Match:"), c);
		c.gridx = 1;
		listPanel.add(new JLabel("Replace:"), c);
		c.gridx = 0;
		c.gridy++;
		listPanel.add(matchInputText, c);
		c.gridx = 1;
		listPanel.add(replaceInputText, c);
		c.gridx = 2;
		listPanel.add(addEntryButton, c);

		c.gridy++;
		for (MatchAndReplace matchAndReplace : matchAndReplaceList) {
			c.gridx = 0;
			listPanel.add(getFormattedLabel(matchAndReplace.getMatch()), c);
			c.gridx = 1;
			listPanel.add(getFormattedLabel(matchAndReplace.getReplace()), c);
			JButton deleteEntryBtn = new JButton();
			deleteEntryBtn.setIcon(new ImageIcon(this.getClass().getClassLoader().getResource("delete.png")));
			deleteEntryBtn.addActionListener(new ActionListener() {

				@Override
				public void actionPerformed(ActionEvent e) {
					removeGivenMatch(matchAndReplace.getMatch());
					updateMatchAndReplaceList();
					SwingUtilities.getWindowAncestor((Component) e.getSource()).pack();
				}
			});
			c.gridx = 2;
			listPanel.add(deleteEntryBtn, c);
			c.gridy++;
		}
		c.insets = new Insets(10, 5, 10, 0);
		listPanel.add(okButton, c);
		listPanel.revalidate();
		listPanel.repaint();
		pack();
	}
	
	private JLabel getFormattedLabel(String text) {
		String formattedText;
		if(text.length() > 28) {
			formattedText = text.substring(0, 25) + "...";
		}
		else {
			formattedText = text;
		}
		JLabel label = new JLabel(formattedText);
		label.setToolTipText(text);
		return label;
	}
	
	private void addMatchAndReplace(String matchText, String replaceText) {
		if (!matchText.equals("") && !replaceText.equals("")) {
			removeGivenMatch(matchText);
			matchAndReplaceList.add(new MatchAndReplace(matchText, replaceText));
		}
	}
	
	private boolean removeGivenMatch(String match) {
		Iterator<MatchAndReplace> it = matchAndReplaceList.iterator();
		while(it.hasNext()) {
			MatchAndReplace m = it.next();
			if(m.getMatch().equals(match)) {
				it.remove();
				return true;
			}
		}
		return false;
	}

}
