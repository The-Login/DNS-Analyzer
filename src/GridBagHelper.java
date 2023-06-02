import javax.swing.*;
import java.awt.*;

public class GridBagHelper {
    public static void setGridBagLayout(JComponent jComponent, GridBagLayout gridBagLayout,GridBagConstraints gridBagConstraints,int gridx,int gridy,int gridwidth,int gridheight,int weightx, int weighty,int fill){
        gridBagConstraints.gridx = gridx;
        gridBagConstraints.gridy = gridy;
        gridBagConstraints.gridwidth = gridwidth;
        gridBagConstraints.gridheight = gridheight;
        gridBagConstraints.weightx = weightx;
        gridBagConstraints.weighty = weighty;
        gridBagConstraints.fill = fill;
        gridBagLayout.setConstraints(jComponent, gridBagConstraints);
    }
}
