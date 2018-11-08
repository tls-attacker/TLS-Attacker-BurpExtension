/**
 * TLS-Attacker-BurpExtension
 * 
 * Copyright 2018 Ruhr University Bochum / Hackmanit GmbH
 * 
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0/
 */
package de.rub.nds.burp.utilities.table;

import java.util.ArrayList;
import javax.swing.table.AbstractTableModel;

/**
 * Helper class for the class Table.
 * 
 * @author Nurullah Erinola
 */
public class TableModel extends AbstractTableModel{
    
    private ArrayList<TableEntry> list;
    private String[] columnNames = {"#", "Host", "Scan Detail", "Report Detail", "Danger Level", "StarTLS", "Implementation", "No color"};

    /**
     * Construct a new Table Helper
     */
    public TableModel() {
        list = new ArrayList<>();
    }

    /**
     * Get the table list.
     * @return The list saved during the construction.
     */
    public ArrayList<TableEntry> getTableList(){
        return list;
    }
    
    /**
     * Add a row to the list and the table.
     * @param entry The new row.
     */
    public void addRow(TableEntry entry){
        list.add(entry);
        fireTableRowsInserted(list.size(),list.size());
    }
    
    /**
     * Remove all entries from the table list.
     */
    public void clear(){
        list.clear();
        fireTableDataChanged();
    }
    
    /**
     * Get the number of rows.
     * @return Number of rows.
     */
    @Override
    public int getRowCount()
    {
        return list.size();
    }

    /**
     * 
     * @return Number of columns.
     */
    @Override
    public int getColumnCount()
    {
        return columnNames.length;
    }

    /**
     * Get the name of the column.
     * @param columnIndex Index of the column.
     * @return The name of the column.
     */
    @Override
    public String getColumnName(int columnIndex)
    {
        return columnNames[columnIndex];
    }

    /**
     * Get the class of the column.
     * @param columnIndex Index of the column.
     * @return The class of the column.
     */
    @Override
    public Class<?> getColumnClass(int columnIndex)
    {
        return getValueAt(0, columnIndex).getClass();
    }

    /**
     * Get the value at a position.
     * @param rowIndex The row.
     * @param columnIndex The column.
     * @return Value for the specified entry. Null if not found.
     */
    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
        TableEntry entry = list.get(rowIndex);

        switch (columnIndex)
        {
            case 0:
                return entry.getCounter();
            case 1:
                return entry.getHost();
            case 2:
                return entry.getScanDetail();
            case 3:
                return entry.getReportDetail();
            case 4:
                return entry.getDanger();
            case 5:
                return entry.getStarTls();
            case 6:
                return entry.getImplementation();   
            case 7:
                return entry.getNoColor();
            default:
                return null;
        }
    }
    
    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return false;
    }
}
