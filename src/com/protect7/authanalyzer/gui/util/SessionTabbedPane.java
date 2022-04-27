package com.protect7.authanalyzer.gui.util;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JTabbedPane;
import com.protect7.authanalyzer.gui.listener.CloneSessionListener;
import com.protect7.authanalyzer.gui.listener.DeleteSessionListener;
import com.protect7.authanalyzer.gui.listener.NewSessionListener;
import com.protect7.authanalyzer.gui.listener.RenameSessionListener;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

public class SessionTabbedPane extends JTabbedPane {

	private static final long serialVersionUID = -2210225276859158505L;
	private DeleteSessionListener deleteSessionListener = null;
	private RenameSessionListener renameSessionListener = null;
	private NewSessionListener newSessionListener = null;
	private CloneSessionListener cloneSessionListener = null;
	private boolean modifEnabled = true;

	public SessionTabbedPane() {
		super();
		addTabNewSession();
	}
	
	public void addDeleteSessionListener(DeleteSessionListener deleteSessionListener) {
		this.deleteSessionListener = deleteSessionListener;
	}
	
	public void addRenameSessionListener(RenameSessionListener renameSessionListener) {
		this.renameSessionListener = renameSessionListener;
	}
	
	public void addNewSessionListener(NewSessionListener newSessionListener) {
		this.newSessionListener = newSessionListener;
	}
	
	public void addCloneSessionListener(CloneSessionListener cloneSessionListener) {
		this.cloneSessionListener = cloneSessionListener;
	}
	
	public void setModifEnabled(boolean modifEnabled) {
		this.modifEnabled = modifEnabled;
	}
	
	@Override
	public void setTitleAt(int index, String title) {
		super.setTitleAt(index, title);
		setTabComponentAt(index, new SessionTab(null, title, index));
	}

	@Override
	public void addTab(String title, Component component) {
		int index = getTabCount() - 1;
		insertTab(title, null, component, null, index);
		setTabComponentAt(index, new SessionTab(component, title, index));
		getTabComponentAt(index).addMouseListener(new MouseAdapter() {                      
            @Override
            public void mouseClicked(MouseEvent e) {
            	setSelectedIndex(index);
            }             
        });
	}
	
	@Override
	public void removeAll() {
		super.removeAll();
		addTabNewSession();
	}

	public void addTabNewSession() {
		String text = "...";
		int location = getTabCount();
		insertTab(text, null, null, null, location);
		setTabComponentAt(location, new AddSessionTab(null, text));
		setEnabledAt(location, false);
	}

	public class SessionTab extends JPanel {

		private static final long serialVersionUID = 3898047768157638854L;

		public SessionTab(final Component tab, String title, int index) {
			FlowLayout flowLayout = new FlowLayout(FlowLayout.CENTER, 3, 3);
			setLayout(flowLayout);
			JLabel titleLabel = new JLabel(title+" ");
			add(titleLabel);
			titleLabel.setToolTipText("Rename Session");
			titleLabel.addMouseListener(new MouseAdapter() {
				@Override
				public void mouseClicked(MouseEvent e) {
					setSelectedIndex(index);
	            	if(e.getClickCount() == 2 && canModify()) {
	            		if(renameSessionListener != null) {
	            			renameSessionListener.renameSession(title);
	            		}
	            	}
				}
			});
			JButton deleteButton = new JButton("X");
			deleteButton.setMargin(new Insets(0, 0, 0, 0));
			deleteButton.setToolTipText("Delete Session");
			deleteButton.addActionListener(new ActionListener() {
				
				@Override
				public void actionPerformed(ActionEvent e) {
					if(canModify() && deleteSessionListener != null) {
						deleteSessionListener.deleteSession(title);
					}
				}
			});
			add(deleteButton);
			
		}
	}

	public class AddSessionTab extends JPanel {
		
		private static final long serialVersionUID = 9025776536297919810L;

		public AddSessionTab(final Component tab, String title) {

			setOpaque(false);
			FlowLayout flowLayout = new FlowLayout(FlowLayout.CENTER, 3, 3);
			setLayout(flowLayout);
			JLabel titleLabel = new JLabel(title);
			add(titleLabel);
			titleLabel.addMouseListener(new MouseAdapter() {
				@Override
				public void mouseReleased(MouseEvent event) {
					JPopupMenu contextMenu = new JPopupMenu();
					JMenuItem newSessionItem = new JMenuItem("Add New Session");
					newSessionItem.addActionListener(new ActionListener() {
						
						@Override
						public void actionPerformed(ActionEvent e) {
							if(canModify() && newSessionListener != null) {
								newSessionListener.newSession();
							}
						}
					});
					contextMenu.add(newSessionItem);
					JMenuItem cloneSessionItem = new JMenuItem("Clone Selected Session");
					cloneSessionItem.addActionListener(new ActionListener() {
						
						@Override
						public void actionPerformed(ActionEvent e) {
							if(canModify() && cloneSessionListener != null) {
								cloneSessionListener.cloneSession();
							}
						}
					});
					contextMenu.add(cloneSessionItem);
					contextMenu.show(event.getComponent(), event.getX(), event.getY());
				}
			});
		}
	}
	
	public boolean canModify() {
		if(!modifEnabled) {
			JOptionPane.showMessageDialog(this, "Auth Analyzer running...\nCurrently no modifications possible!\n", "Modification not possible", JOptionPane.WARNING_MESSAGE);
			return false;
		}
		return true;
	}
}