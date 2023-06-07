import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.*;
import burp.api.montoya.extension.ExtensionUnloadingHandler;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.axis.ValueAxis;
import org.jfree.data.xy.XYSeries;
import org.jfree.data.xy.XYSeriesCollection;
import org.jfree.chart.plot.XYPlot;
import org.jfree.data.xy.XYDataset;

import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.List;

public class DNSAnalyzer implements BurpExtension {
    private static MontoyaApi montoyaApi;
    private DNSAnalyzerTab dnsAnalyzerTab;
    private Collaborator collaborator;
    private CollaboratorClient collaboratorClient;
    private CollaboratorPayload collaboratorPayload;
    private InteractionMonitor interactionMonitor;
    private int monitoringInterval = 10000;
    private static final List<Interaction> interactionLog = new ArrayList<Interaction>();

    @Override
    public void initialize(MontoyaApi api) {
        montoyaApi = api;
        this.collaborator = this.montoyaApi.collaborator();
        this.collaboratorClient = collaborator.createClient();

        //Register DNS Analyzer suite
        dnsAnalyzerTab = new DNSAnalyzerTab(this);
        api.userInterface().registerSuiteTab("DNS Analyzer", dnsAnalyzerTab);

        //start polling for interactions
        interactionMonitor = new InteractionMonitor();
        new Thread(interactionMonitor).start();
    }

    public class InteractionMonitor implements Runnable, ExtensionUnloadingHandler {
        boolean stop = false;

        public void run() {
            try {
                while (!stop) {
                    Thread.sleep(monitoringInterval);
                    collaboratorClient.getAllInteractions().forEach(interaction -> processInteraction(interaction));
                }
            } catch (InterruptedException e) {
                montoyaApi.logging().logToOutput("Interrupted");
            } catch (Exception e) {
                montoyaApi.logging().logToOutput("Error fetching/handling interactions: " + e.getMessage());
            }

            montoyaApi.logging().logToOutput("Shutting down collaborator monitor thread");
        }

        public void processInteraction(Interaction interaction){
            montoyaApi.logging().logToOutput("Processing interaction: " + interaction.id());
            if (interaction.type() == InteractionType.DNS) {
                int row = interactionLog.size();
                interactionLog.add(interaction);
                dnsAnalyzerTab.mainTab.analysisPanel.logTableModel.fireTableRowsInserted(row, row);
            }
        }

        public void extensionUnloaded() {
            Thread.currentThread().interrupt();
        }
    }
    public class DNSAnalyzerTab extends JComponent {

        DNSAnalyzer dnsAnalyzer;
        MainTab mainTab;
        HelpTab helpTab;
        JTabbedPane jTabbedPane;
        GridBagLayout gridBagLayout;
        GridBagConstraints gridBagConstraints;
        public DNSAnalyzerTab(DNSAnalyzer dnsAnalyzer) {
            this.dnsAnalyzer = dnsAnalyzer;
            gridBagLayout = new GridBagLayout();
            gridBagConstraints = new GridBagConstraints();

            gridBagConstraints.fill = GridBagConstraints.BOTH;
            gridBagConstraints.weightx = 1.0;
            gridBagConstraints.weighty = 1.0;
            gridBagLayout.setConstraints(this,gridBagConstraints);

            setLayout(gridBagLayout);

            jTabbedPane = new JTabbedPane();
            gridBagLayout.setConstraints(jTabbedPane,gridBagConstraints);

            mainTab = new MainTab();
            helpTab = new HelpTab();

            jTabbedPane.add("DNS Analyzer",mainTab);
            jTabbedPane.add("Help",helpTab);

            add(jTabbedPane);

            montoyaApi.userInterface().applyThemeToComponent(this);
        }


        private class MainTab extends JComponent {
            JPanel tabContent;
            HeaderPanel headerPanel;
            ConfigurationPanel configurationPanel;
            AnalysisPanel analysisPanel;

            MainTab() {
                gridBagLayout.setConstraints(this,gridBagConstraints);
                setLayout(gridBagLayout);

                gridBagConstraints.insets = new Insets(10,10,10,10);
                configurationPanel = new ConfigurationPanel();
                analysisPanel = new AnalysisPanel();
                gridBagConstraints.insets = new Insets(10,0,0,0);

                GridBagHelper.setGridBagLayout(configurationPanel,gridBagLayout,gridBagConstraints,0,1,1,1,0,0,GridBagConstraints.BOTH);

                gridBagConstraints.insets = new Insets(0,0,0,0);

                add(configurationPanel);
                GridBagHelper.setGridBagLayout(analysisPanel,gridBagLayout,gridBagConstraints,0,2,1,1,1,1,GridBagConstraints.BOTH);

                add(analysisPanel);

                montoyaApi.userInterface().applyThemeToComponent(this);
            }

            private class HeaderPanel extends JComponent {
                JLabel header;

                HeaderPanel() {
                    setLayout(new FlowLayout());
                    header = new JLabel("<html><center><h1>DNS Analyzer</h1>Analyze Burp Collaborator DNS data for vulnerable DNS resolvers!</center></html>");
                    header.putClientProperty("html.disable", false);
                    add(header);
                }
            }

            private class ConfigurationPanel extends JComponent {
                CopyButton copyButton;
                PollButton pollButton;
                JSeparator jSeparatorVertical;

                JLabel intervalLabel;

                IntervalSlider intervalSlider;
                JSeparator jSeparatorHorizontal;
                JProgressBar listenerProgress;
                public ConfigurationPanel() {
                    setLayout(gridBagLayout);

                    copyButton = new CopyButton();
                    jSeparatorVertical = new JSeparator(JSeparator.VERTICAL);
                    intervalLabel = new JLabel("Polling interval: " + dnsAnalyzer.monitoringInterval + "ms");
                    intervalSlider = new IntervalSlider();
                    pollButton = new PollButton();
                    jSeparatorHorizontal = new JSeparator(JSeparator.HORIZONTAL);
                    listenerProgress = new JProgressBar(1, 1);
                    listenerProgress.setIndeterminate(true);

                    GridBagHelper.setGridBagLayout(copyButton,gridBagLayout,gridBagConstraints,0,0,1,1,0,0,GridBagConstraints.NONE);
                    add(copyButton);

                    GridBagHelper.setGridBagLayout(jSeparatorVertical,gridBagLayout,gridBagConstraints,1,0,1,1,0,1,GridBagConstraints.VERTICAL);
                    add(jSeparatorVertical);

                    GridBagHelper.setGridBagLayout(intervalLabel,gridBagLayout,gridBagConstraints,2,0,1,1,0,0,GridBagConstraints.BOTH);
                    add(intervalLabel);

                    GridBagHelper.setGridBagLayout(intervalSlider,gridBagLayout,gridBagConstraints,3,0,1,1,0,0,GridBagConstraints.BOTH);
                    add(intervalSlider);

                    GridBagHelper.setGridBagLayout(pollButton,gridBagLayout,gridBagConstraints,4,0,1,1,0,0,GridBagConstraints.NONE);
                    add(pollButton);

                    GridBagHelper.setGridBagLayout(jSeparatorHorizontal,gridBagLayout,gridBagConstraints,0,1,20,1,1,0,GridBagConstraints.BOTH);
                    add(jSeparatorHorizontal);

                }

                private class CopyButton extends JButton {
                    CopyButton() {
                        this.setText("Copy to Clipboard");
                        this.setFont(new Font(this.getFont().getName(),Font.BOLD,this.getFont().getSize()));
                        this.setBackground(Color.decode("#d86633"));
                        this.setForeground(Color.WHITE);
                        this.setBorderPainted(false);
                        this.addActionListener(new CopyToClipboard());
                    }

                    private class CopyToClipboard implements ActionListener {
                        public void actionPerformed(ActionEvent e) {
                            collaboratorPayload = collaboratorClient.generatePayload();
                            montoyaApi.logging().logToOutput("Generated new Collaborator payload: " + collaboratorPayload.toString());
                            Clipboard clipBoard = Toolkit.getDefaultToolkit().getSystemClipboard();
                            clipBoard.setContents(new StringSelection(collaboratorPayload.toString()), null);
                        }
                    }
                }

                private class PollButton extends JButton {
                    PollButton() {
                        this.setText("Poll now");
                        this.addActionListener(new PollNow());
                    }

                    private class PollNow implements ActionListener {
                        public void actionPerformed(ActionEvent e) {
                            collaboratorClient.getAllInteractions().forEach(interaction -> interactionMonitor.processInteraction(interaction));
                        }
                    }

                }

                private class IntervalSlider extends JSlider {
                    IntervalSlider() {
                        this.setMinimum(1000);
                        this.setMaximum(60000);
                        this.setValue(dnsAnalyzer.monitoringInterval);
                        this.addChangeListener(new SliderChange());
                    }

                    private class SliderChange implements ChangeListener {

                        public void stateChanged(ChangeEvent e) {
                            int sliderValue = intervalSlider.getValue();
                            intervalLabel.setText("Polling interval: " + sliderValue + "ms");
                            dnsAnalyzer.monitoringInterval = sliderValue;
                        }
                    }

                }

            }

            private class AnalysisPanel extends JComponent {
                LogTableModel logTableModel;
                LogTable logTable;
                JSplitPane splitPane;
                JScrollPane scrollPaneLogTable;
                JScrollPane scrollPaneResultPanel;
                ResultPanel resultPanel;

                AnalysisPanel() {
                    setLayout(gridBagLayout);

                    logTableModel = new LogTableModel();
                    logTable = new LogTable(logTableModel);
                    logTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
                    logTable.getColumnModel().getColumn(0).setPreferredWidth(50);
                    logTable.getColumnModel().getColumn(1).setPreferredWidth(400);
                    logTable.getColumnModel().getColumn(2).setPreferredWidth(200);
                    logTable.getColumnModel().getColumn(3).setPreferredWidth(100);
                    logTable.getColumnModel().getColumn(4).setPreferredWidth(100);
                    logTable.getColumnModel().getColumn(5).setPreferredWidth(200);
                    logTable.getColumnModel().getColumn(6).setPreferredWidth(200);
                    logTable.getColumnModel().getColumn(7).setPreferredWidth(200);
                    TableRowSorter<TableModel> sorter = new TableRowSorter<TableModel>(logTable.getModel());
                    logTable.setRowSorter(sorter);

                    resultPanel = new ResultPanel();

                    scrollPaneLogTable = new JScrollPane(logTable);
                    scrollPaneResultPanel = new JScrollPane(resultPanel);


                    splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                    splitPane.setTopComponent(scrollPaneLogTable);
                    splitPane.setBottomComponent(scrollPaneResultPanel);

                    GridBagHelper.setGridBagLayout(splitPane,gridBagLayout,gridBagConstraints,0,0,1,1,1,1,GridBagConstraints.BOTH);
                    add(splitPane);
                    splitPane.setResizeWeight(0.0d);
                }

                class LogTableModel extends AbstractTableModel {

                    @Override
                    public int getRowCount() {
                        return interactionLog.size();
                    }

                    @Override
                    public int getColumnCount() {
                        return 8;
                    }

                    @Override
                    public Object getValueAt(int rowIndex, int columnIndex) {
                        Interaction interaction = interactionLog.get(rowIndex);

                        switch (columnIndex) {
                            case 0:
                                return interactionLog.indexOf(interaction);
                            case 1:
                                return interaction.id();
                            case 2:
                                return interaction.clientIp().getHostAddress();
                            case 3:
                                return interaction.clientPort();
                            case 4:
                                return Short.toUnsignedInt(ByteBuffer.wrap(interaction.dnsDetails().get().query().getBytes()).getShort());
                            case 5:
                                return interaction.dnsDetails().get().queryType();
                            case 6:
                                return DNSAnalysisUtils.getPublicDNSResolver(interaction.clientIp().getHostAddress());
                            case 7:
                                return interaction.timeStamp().toString();
                            default:
                                return "";
                        }
                    }

                    @Override
                    public Class getColumnClass(int column) {
                        switch (column) {
                            case 0:
                                return Integer.class;
                            case 1:
                                return String.class;
                            case 2:
                                return String.class;
                            case 3:
                                return Integer.class;
                            case 4:
                                return Integer.class;
                            case 5:
                                return String.class;
                            case 6:
                                return String.class;
                            case 7:
                                return String.class;
                            default:
                                return String.class;
                        }
                    }

                    @Override
                    public String getColumnName(int columnIndex) {
                        switch (columnIndex) {
                            case 0:
                                return "#";
                            case 1:
                                return "Collaborator ID";
                            case 2:
                                return "Resolver IP";
                            case 3:
                                return "Source Port";
                            case 4:
                                return "DNS ID";
                            case 5:
                                return "Query Type";
                            case 6:
                                return "Public Resolver";
                            case 7:
                                return "Timestamp";
                            default:
                                return "";
                        }
                    }
                }

                private class LogTable extends JTable {
                    public LogTable(TableModel tableModel) {
                        super(tableModel);
                    }


                    @Override
                    public void valueChanged(ListSelectionEvent e) {
                        int[] selectedRows = logTable.getSelectedRows();
                        Interaction[] selectedInteractions = new Interaction[selectedRows.length];
                        for (int i = 0; i < selectedRows.length;i++) {
                            int modelIndex = logTable.getRowSorter().convertRowIndexToModel(selectedRows[i]);
                            selectedInteractions[i] = interactionLog.get(modelIndex);
                        }
                        resultPanel.updateResultPanel(new DNSAnalysisUtils.DNSAnalysisResults(selectedInteractions));

                        super.valueChanged(e);
                    }
                }

                private class ResultPanel extends JComponent{

                    AnalysisTitle analysisTitle;
                    AnalysisText analysisText;
                    AnalysisPlots analysisPlots;
                    List<JComponent> analysisElements = new ArrayList<JComponent>();
                    InfoHeader infoHeader;

                    JSeparator jSeparatorHorizontal;
                    ResultPanel(){
                        setLayout(gridBagLayout);

                        infoHeader = new InfoHeader();
                        GridBagHelper.setGridBagLayout(infoHeader,gridBagLayout,gridBagConstraints,0,0,2,1,0,0,GridBagConstraints.BOTH);
                        add(infoHeader);

                    }

                    public void updateResultPanel(DNSAnalysisUtils.DNSAnalysisResults dnsAnalysisResults){
                        infoHeader.jSeparatorHorizontal.setVisible(false);

                        for (JComponent analysisElement:analysisElements){
                            remove(analysisElement);
                        }

                        analysisElements.clear();

                        if (dnsAnalysisResults.totalInteractions < DNSAnalysisUtils.minimumRequiredValues){
                            infoHeader.infoText.setText(String.format("<h1>Please select more than %s rows!</h1>",DNSAnalysisUtils.minimumRequiredValues));
                            infoHeader.setVisible(true);
                            GridBagHelper.setGridBagLayout(infoHeader,gridBagLayout,gridBagConstraints,0,0,2,1,0,0,GridBagConstraints.BOTH);

                            revalidate();
                            repaint();
                            return;
                        }

                        gridBagConstraints.insets = new Insets(0,10,0,10);

                        GridBagHelper.setGridBagLayout(infoHeader,gridBagLayout,gridBagConstraints,0,0,3,1,1,0,GridBagConstraints.BOTH);

                        infoHeader.infoText.setText(String.format("<h1>Kaminsky Status: <b style=\"color: #%s;\">%s</b></h1>",dnsAnalysisResults.overallRating.ratingColorHex,dnsAnalysisResults.overallRating.ratingText));
                        infoHeader.jSeparatorHorizontal.setVisible(true);

                        for (int i = 0; i < dnsAnalysisResults.dnsAnalysisResults.length; i++){
                            analysisTitle = new AnalysisTitle(dnsAnalysisResults.dnsAnalysisResults[i]);
                            analysisElements.add(analysisTitle);
                            analysisText = new AnalysisText(dnsAnalysisResults.dnsAnalysisResults[i]);
                            analysisElements.add(analysisText);
                            analysisPlots = new AnalysisPlots(dnsAnalysisResults.dnsAnalysisResults[i]);
                            analysisElements.add(analysisPlots);
                            jSeparatorHorizontal = new JSeparator(SwingConstants.HORIZONTAL);

                            GridBagHelper.setGridBagLayout(analysisTitle,gridBagLayout,gridBagConstraints,0,1 + i*2,1,1,1,1,GridBagConstraints.BOTH);
                            add(analysisTitle);

                            GridBagHelper.setGridBagLayout(analysisText,gridBagLayout,gridBagConstraints,0,2 + i*2,1,1,1,1,GridBagConstraints.BOTH);
                            add(analysisText);

                            GridBagHelper.setGridBagLayout(analysisPlots,gridBagLayout,gridBagConstraints,1,2 + i*2,1,1,1,1,GridBagConstraints.BOTH);
                            add(analysisPlots);
                        }

                        javax.swing.SwingUtilities.invokeLater(new Runnable() {
                            public void run() {
                                scrollPaneResultPanel.getVerticalScrollBar().setValue(0);
                            }
                        });
                    }

                    private class InfoHeader extends JComponent{
                        JTextPane infoText;
                        JSeparator jSeparatorHorizontal;
                        InfoHeader(){
                            setLayout(gridBagLayout);
                            infoText = new JTextPane();
                            infoText.setContentType("text/html");
                            infoText.setText("<h1>To start analyzing, click \"Copy to Clipboard\" and generate some DNS traffic to the collaborator domain!</h1>");
                            infoText.setEditable(false);
                            infoText.setBackground(null);
                            infoText.setBorder(null);

                            jSeparatorHorizontal = new JSeparator(SwingConstants.HORIZONTAL);
                            jSeparatorHorizontal.setVisible(false);

                            GridBagHelper.setGridBagLayout(infoText,gridBagLayout,gridBagConstraints,0,0,1,1,1,1,GridBagConstraints.BOTH);
                            add(infoText);


                            GridBagHelper.setGridBagLayout(jSeparatorHorizontal,gridBagLayout,gridBagConstraints,0,1,20,1,1,1,GridBagConstraints.BOTH);
                            add(jSeparatorHorizontal);
                        }
                    }

                    private class AnalysisTitle extends JComponent{
                        JTextPane analysisTitle;
                        AnalysisTitle(DNSAnalysisUtils.DNSAnalysisResults.DNSAnalysisResult dnsAnalysisResult){
                            setLayout(gridBagLayout);
                            analysisTitle = new JTextPane();
                            analysisTitle.setContentType("text/html");
                            analysisTitle.setText(String.format("<h1><u>%s</u></h1>",dnsAnalysisResult.resolverIP));
                            analysisTitle.setEditable(false);
                            analysisTitle.setBackground(null);
                            analysisTitle.setBorder(null);

                            GridBagHelper.setGridBagLayout(analysisTitle,gridBagLayout,gridBagConstraints,0,0,1,1,1,1,GridBagConstraints.BOTH);
                            add(analysisTitle);
                        }
                    }
                    private class AnalysisText extends JComponent{
                        JTextPane analysisText;
                        int[] sourcePorts;
                        int[] dnsIds;

                        AnalysisText(DNSAnalysisUtils.DNSAnalysisResults.DNSAnalysisResult dnsAnalysisResult){
                            setLayout(gridBagLayout);
                            analysisText = new JTextPane();
                            analysisText.setContentType("text/html");
                            analysisText.setText(String.format(DNSAnalysisUtils.analysisText,dnsAnalysisResult.totalInteractions,
                                    dnsAnalysisResult.totalResolverIPs,
                                    String.join(", ",dnsAnalysisResult.publicResolvers),

                                    dnsAnalysisResult.sourcePortResult.rating.ratingColorHex,dnsAnalysisResult.sourcePortResult.rating.ratingText,
                                    dnsAnalysisResult.sourcePortResult.standardDeviation,
                                    dnsAnalysisResult.sourcePortResult.directionBias,
                                    dnsAnalysisResult.sourcePortResult.uniqueValues,dnsAnalysisResult.totalInteractions,
                                    dnsAnalysisResult.sourcePortResult.lowestValue,
                                    dnsAnalysisResult.sourcePortResult.highestValue,
                                    dnsAnalysisResult.sourcePortResult.difference,
                                    dnsAnalysisResult.sourcePortResult.valueRangeBits,

                                    dnsAnalysisResult.dnsIdResult.rating.ratingColorHex,dnsAnalysisResult.dnsIdResult.rating.ratingText,
                                    dnsAnalysisResult.dnsIdResult.standardDeviation,
                                    dnsAnalysisResult.dnsIdResult.directionBias,
                                    dnsAnalysisResult.dnsIdResult.uniqueValues,dnsAnalysisResult.totalInteractions,
                                    dnsAnalysisResult.dnsIdResult.lowestValue,
                                    dnsAnalysisResult.dnsIdResult.highestValue,
                                    dnsAnalysisResult.dnsIdResult.difference,
                                    dnsAnalysisResult.dnsIdResult.valueRangeBits
                                    ));

                            analysisText.setEditable(false);
                            analysisText.setBackground(null);
                            analysisText.setBorder(null);

                            GridBagHelper.setGridBagLayout(analysisText,gridBagLayout,gridBagConstraints,0,0,1,1,1,1,GridBagConstraints.BOTH);
                            add(analysisText);
                        }

                    }

                    private class AnalysisPlots extends JComponent{
                        int[] sourcePorts;
                        int[] dnsIds;
                        JTextPane analysisPlotsHeader;
                        AnalysisPlots(DNSAnalysisUtils.DNSAnalysisResults.DNSAnalysisResult dnsAnalysisResult){
                            setLayout(gridBagLayout);

                            analysisPlotsHeader = new JTextPane();
                            analysisPlotsHeader.setContentType("text/html");
                            analysisPlotsHeader.setText("<h1>Scatter Plots</h1>");
                            analysisPlotsHeader.setEditable(false);
                            analysisPlotsHeader.setBackground(null);
                            analysisPlotsHeader.setBorder(null);

                            gridBagConstraints.gridx = 0;
                            gridBagConstraints.gridy = 0;
                            gridBagConstraints.gridwidth = 1;
                            gridBagConstraints.gridheight = 1;
                            gridBagConstraints.weightx = 1;
                            gridBagConstraints.weighty = 1;
                            gridBagConstraints.fill = GridBagConstraints.BOTH;
                            gridBagLayout.setConstraints(analysisPlotsHeader, gridBagConstraints);

                            add(analysisPlotsHeader);

                            ScatterPlot sourcePortScatterPlot;
                            sourcePortScatterPlot = new ScatterPlot(String.format("Source Ports (%s)",dnsAnalysisResult.resolverIP),"Source port by request","Request Number","Source Port",dnsAnalysisResult.sourcePorts);
                            GridBagHelper.setGridBagLayout(sourcePortScatterPlot,gridBagLayout,gridBagConstraints,0,1,1,1,0,0,GridBagConstraints.BOTH);
                            add(sourcePortScatterPlot);

                            ScatterPlot dnsIdScatterPlot;
                            dnsIdScatterPlot = new ScatterPlot(String.format("DNS IDs (%s)",dnsAnalysisResult.resolverIP),"DNS ID per request","Request Number","DNS ID",dnsAnalysisResult.dnsIds);
                            GridBagHelper.setGridBagLayout(dnsIdScatterPlot,gridBagLayout,gridBagConstraints,1,1,1,1,0,0,GridBagConstraints.BOTH);
                            add(dnsIdScatterPlot);
                        }

                        private class ScatterPlot extends JPanel {
                            private List<Point> points;

                            public ScatterPlot(String title,String description, String xAxis, String yAxis, int[] data) {
                                this.setPreferredSize(new Dimension(700,700));

                                Color textColor = UIManager.getColor("windowText");
                                String burpFontName = UIManager.getFont("TextArea.font").getFontName();
                                Font titleFont = new Font(burpFontName, Font.BOLD,20);
                                Font textFont = new Font(burpFontName, Font.BOLD,15);
                                Font tickFont = new Font(burpFontName, Font.PLAIN,12);

                                XYDataset dataset = createDataset(description,data);
                                JFreeChart chart = ChartFactory.createScatterPlot(title,xAxis,yAxis, dataset);
                                chart.setBackgroundPaint(new Color(0, 0, 0, 0));
                                chart.getTitle().setFont(titleFont);
                                chart.getTitle().setPaint(textColor);
                                chart.removeLegend();

                                XYPlot plot = (XYPlot)chart.getPlot();
                                plot.setOutlinePaint(textColor);
                                ValueAxis rangeAxis = plot.getRangeAxis();
                                rangeAxis.setRange(0, 65535);
                                rangeAxis.setStandardTickUnits(NumberAxis.createIntegerTickUnits());
                                rangeAxis.setLabelPaint(textColor);
                                rangeAxis.setTickLabelPaint(textColor);
                                rangeAxis.setLabelFont(textFont);
                                rangeAxis.setTickLabelFont(tickFont);
                                ValueAxis domainAxis = plot.getDomainAxis();
                                domainAxis.setStandardTickUnits(NumberAxis.createIntegerTickUnits());
                                domainAxis.setLabelPaint(textColor);
                                domainAxis.setTickLabelPaint(textColor);
                                domainAxis.setLabelFont(textFont);
                                domainAxis.setTickLabelFont(tickFont);
                                plot.setBackgroundPaint(new Color(0, 0, 0, 0));

                                ChartPanel panel = new ChartPanel(chart);

                                setLayout(gridBagLayout);
                                GridBagHelper.setGridBagLayout(panel,gridBagLayout,gridBagConstraints,0,0,1,1,1,1,GridBagConstraints.BOTH);
                                add(panel);
                            }

                            private XYDataset createDataset(String description,int[] data){
                                XYSeriesCollection dataset = new XYSeriesCollection();

                                XYSeries series = new XYSeries(description);

                                for(int i = 0;i < data.length;i++) {
                                    series.add(i,data[i]);
                                }

                                dataset.addSeries(series);
                                return dataset;
                            }


                        }

                    }

                }
            }
        }
        private class HelpTab extends JComponent {
            HelpText helpText;
            JScrollPane helpScrollPane;

            HelpTab(){
                gridBagConstraints.insets = new Insets(10,10,10,10);
                gridBagLayout.setConstraints(this,gridBagConstraints);
                setLayout(gridBagLayout);

                helpText = new HelpText();

                helpScrollPane = new JScrollPane(helpText);
                helpScrollPane.setBorder(null);
                helpScrollPane.setBackground(null);

                gridBagConstraints.insets = new Insets(0,0,0,0);
                GridBagHelper.setGridBagLayout(helpScrollPane,gridBagLayout,gridBagConstraints,0,0,1,1,1,1,GridBagConstraints.BOTH);
                add(helpScrollPane);

            }
            private class HelpText extends JComponent{
                JTextPane helpText;
                HelpText(){
                    gridBagConstraints.insets = new Insets(10,10,10,10);
                    gridBagLayout.setConstraints(this,gridBagConstraints);
                    setLayout(gridBagLayout);
                    helpText = new JTextPane();
                    helpText.setContentType("text/html");
                    helpText.setText(String.format(DNSAnalysisUtils.helpText,DNSAnalysisUtils.minimumRequiredValues));
                    helpText.setEditable(false);
                    helpText.setBackground(null);
                    helpText.setBorder(null);
                    helpText.setEnabled(true);
                    helpText.addHyperlinkListener(new HyperlinkListener() {
                        @Override public void hyperlinkUpdate(HyperlinkEvent e) {
                            if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED) {
                                Desktop desktop = Desktop.getDesktop();
                                try {
                                    desktop.browse(e.getURL().toURI());
                                } catch (Exception exception) {
                                    exception.printStackTrace();
                                }
                            }
                        }
                    });

                    GridBagHelper.setGridBagLayout(helpText,gridBagLayout,gridBagConstraints,0,1,1,1,1,1,GridBagConstraints.BOTH);
                    add(helpText);
                }
            }
        }
    }
}