import burp.api.montoya.collaborator.Interaction;
import inet.ipaddr.IPAddressString;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public class DNSAnalysisUtils {
    public static final int minimumRequiredValues = 20;
    public static final Map<Integer, Double> standardDeviationRatings = Map.of(
            0, 296.0,
            1, 3980.0,
            2, 20000.0
    );
    public static final Map<Integer, Double> valueRangeBitsRatings = Map.of(
            0, 10.0,
            1, 13.75,
            2, 16.0
    );
    public static final Map<Integer, Double> directionBiasRatings = Map.of(
            0, 0.8,
            1, 0.5,
            2, 0.2
    );

    //https://developers.google.com/speed/public-dns/faq
    public static String[] googleDNSOutgoingIPRanges = {"34.64.0.0/24", "34.64.1.0/24", "34.64.2.0/24", "34.101.0.0/24", "34.101.1.0/24", "34.101.2.0/24", "74.125.16.128/26", "74.125.16.192/26", "74.125.17.128/26", "74.125.17.192/26", "74.125.18.0/25", "74.125.18.128/26", "74.125.18.192/26", "74.125.19.0/25", "74.125.19.128/25", "74.125.40.0/25", "74.125.40.128/26", "74.125.40.192/26", "74.125.41.0/24", "74.125.42.0/24", "74.125.43.0/25", "74.125.43.128/25", "74.125.44.0/24", "74.125.45.0/24", "74.125.46.0/24", "74.125.47.0/24", "74.125.72.0/24", "74.125.73.0/24", "74.125.74.0/24", "74.125.75.0/24", "74.125.76.0/24", "74.125.77.0/24", "74.125.78.0/24", "74.125.79.0/24", "74.125.80.0/24", "74.125.81.0/24", "74.125.92.0/24", "74.125.112.0/24", "74.125.113.0/24", "74.125.114.128/26", "74.125.114.192/26", "74.125.115.0/24", "74.125.177.0/24", "74.125.178.0/25", "74.125.178.128/25", "74.125.179.0/25", "74.125.179.128/26", "74.125.179.192/26", "74.125.180.0/24", "74.125.181.0/25", "74.125.181.128/26", "74.125.181.192/26", "74.125.182.0/24", "74.125.183.0/24", "74.125.184.0/24", "74.125.185.0/25", "74.125.185.128/26", "74.125.185.192/26", "74.125.186.0/25", "74.125.186.128/26", "74.125.186.192/26", "74.125.187.0/25", "74.125.187.128/26", "74.125.187.192/26", "74.125.189.0/24", "74.125.190.0/24", "74.125.191.0/24", "172.217.32.0/25", "172.217.32.128/26", "172.217.32.192/26", "172.217.33.0/25", "172.217.33.128/25", "172.217.34.0/26", "172.217.34.64/26", "172.217.34.128/26", "172.217.34.192/26", "172.217.35.0/26", "172.217.35.64/26", "172.217.35.128/26", "172.217.35.192/26", "172.217.36.0/24", "172.217.37.0/25", "172.217.37.128/26", "172.217.37.192/26", "172.217.38.0/25", "172.217.38.128/26", "172.217.38.192/26", "172.217.39.0/25", "172.217.39.128/26", "172.217.39.192/26", "172.217.40.0/25", "172.217.40.128/26", "172.217.40.192/26", "172.217.41.0/25", "172.217.41.128/26", "172.217.41.192/26", "172.217.42.0/25", "172.217.42.128/26", "172.217.42.192/26", "172.217.43.0/25", "172.217.43.128/26", "172.217.43.192/26", "172.217.44.0/25", "172.217.44.128/26", "172.217.44.192/26", "172.217.45.0/25", "172.217.45.128/25", "172.217.46.0/24", "172.217.47.0/24", "172.253.0.0/25", "172.253.0.128/25", "172.253.1.0/25", "172.253.1.128/26", "172.253.1.192/26", "172.253.2.0/25", "172.253.2.128/25", "172.253.3.0/25", "172.253.3.128/25", "172.253.4.0/25", "172.253.4.128/25", "172.253.5.0/25", "172.253.5.128/25", "172.253.6.0/25", "172.253.6.128/25", "172.253.7.0/24", "172.253.8.0/24", "172.253.9.0/25", "172.253.9.128/25", "172.253.10.0/25", "172.253.10.128/25", "172.253.11.0/25", "172.253.11.128/25", "172.253.12.0/25", "172.253.12.128/25", "172.253.13.0/25", "172.253.13.128/25", "172.253.14.0/24", "172.253.15.0/24", "172.253.192.0/24", "172.253.193.0/24", "172.253.194.0/25", "172.253.194.128/26", "172.253.194.192/26", "172.253.195.0/24", "172.253.196.0/24", "172.253.197.0/24", "172.253.198.0/24", "172.253.199.0/24", "172.253.200.0/24", "172.253.201.0/24", "172.253.202.0/24", "172.253.204.0/24", "172.253.205.0/24", "172.253.206.0/24", "172.253.209.0/24", "172.253.210.0/24", "172.253.211.0/24", "172.253.212.0/24", "172.253.213.0/24", "172.253.214.0/24", "172.253.215.0/24", "172.253.216.0/24", "172.253.217.0/24", "172.253.218.0/24", "172.253.219.0/24", "172.253.220.0/24", "172.253.221.0/24", "172.253.222.0/24", "172.253.223.0/24", "172.253.224.0/24", "172.253.225.0/24", "172.253.226.0/24", "172.253.227.0/24", "172.253.228.0/24", "172.253.229.0/24", "172.253.230.0/24", "172.253.231.0/24", "172.253.232.0/24", "172.253.233.0/24", "172.253.234.0/24", "172.253.235.0/24", "172.253.236.0/24", "172.253.237.0/24", "172.253.238.0/24", "172.253.239.0/24", "172.253.240.0/24", "172.253.241.0/24", "172.253.242.0/24", "172.253.243.0/24", "172.253.244.0/24", "172.253.245.0/24", "172.253.246.0/24", "172.253.247.0/24", "172.253.248.0/24", "172.253.249.0/24", "172.253.250.0/24", "172.253.251.0/24", "172.253.252.0/24", "172.253.253.0/24", "172.253.254.0/24", "172.253.255.0/24", "173.194.90.0/24", "173.194.91.0/24", "173.194.93.0/24", "173.194.94.0/24", "173.194.95.0/24", "173.194.96.0/24", "173.194.97.0/24", "173.194.98.0/24", "173.194.99.0/24", "173.194.100.0/24", "173.194.101.0/24", "173.194.102.0/24", "173.194.103.0/24", "173.194.168.0/25", "173.194.168.128/26", "173.194.168.192/26", "173.194.169.0/24", "173.194.170.0/24", "173.194.171.0/24"};
    //https://www.cloudflare.com/ips/
    public static String[] oneDNSOutgoingIPRanges = {"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "172.64.0.0/13", "131.0.72.0/22", "104.16.0.0/13", "104.24.0.0/14"};
    //ASN30607 and ASN36692
    public static String[] opendnsOutgoingIPRanges = {"204.194.232.0/24", "204.194.234.0/24", "204.194.237.0/24", "204.194.238.0/24", "67.215.64.0/23", "67.215.66.0/24", "67.215.68.0/23", "67.215.70.0/24", "67.215.73.0/24", "67.215.74.0/23", "67.215.76.0/22", "67.215.80.0/24", "67.215.82.0/23", "67.215.84.0/22", "67.215.88.0/21", "146.112.0.0/24", "146.112.2.0/23", "146.112.4.0/23", "146.112.11.0/24", "146.112.12.0/24", "146.112.14.0/23", "146.112.16.0/23", "146.112.18.0/24", "146.112.20.0/22", "146.112.25.0/24", "146.112.26.0/24", "146.112.28.0/22", "146.112.33.0/24", "146.112.34.0/23", "146.112.36.0/23", "146.112.38.0/24", "146.112.40.0/21", "146.112.48.0/20", "146.112.64.0/22", "146.112.66.0/23", "146.112.67.0/24", "146.112.72.0/24", "146.112.78.0/23", "146.112.80.0/21", "146.112.81.0/24", "146.112.82.0/23", "146.112.84.0/23", "146.112.88.0/21", "146.112.92.0/23", "146.112.93.0/24", "146.112.96.0/21", "146.112.97.0/24", "146.112.98.0/24", "146.112.100.0/23", "146.112.101.0/24", "146.112.102.0/23", "146.112.104.0/22", "146.112.106.0/23", "146.112.107.0/24", "146.112.112.0/22", "146.112.114.0/24", "146.112.116.0/22", "146.112.118.0/23", "146.112.119.0/24", "146.112.128.0/19", "146.112.160.0/23", "146.112.162.0/23", "146.112.163.0/24", "146.112.164.0/23", "146.112.165.0/24", "146.112.166.0/23", "146.112.167.0/24", "146.112.168.0/22", "146.112.172.0/23", "146.112.176.0/22", "146.112.184.0/23", "146.112.186.0/24", "146.112.190.0/23", "146.112.192.0/21", "146.112.200.0/23", "146.112.203.0/24", "146.112.204.0/22", "146.112.208.0/22", "146.112.212.0/24", "146.112.214.0/23", "146.112.216.0/23", "146.112.219.0/24", "146.112.221.0/24", "146.112.222.0/23", "146.112.224.0/19", "155.190.0.0/22", "155.190.8.0/23", "155.190.17.0/24", "155.190.18.0/23", "155.190.20.0/23", "155.190.28.0/24", "155.190.33.0/24", "155.190.34.0/23", "155.190.36.0/22", "155.190.43.0/24", "155.190.44.0/24", "155.190.46.0/24", "155.190.48.0/23", "155.190.50.0/24", "155.190.53.0/24", "155.190.54.0/23", "155.190.134.0/24", "155.190.192.0/23", "185.60.84.0/24", "185.60.86.0/23", "208.67.216.0/21", "208.69.32.0/21"};
    //ASN19281
    public static String[] quad9OutgoingIPRanges = {"149.112.112.0/24","149.112.149.0/24","199.249.255.0/24","9.9.9.0/24"};

    public static DNSAnalysisUtils.DNSAnalysisRating valueDistributionRating2(int[] values1, int[] values2) {

        int[] ratings = new int[2];
        ratings[0] = valueDistributionRating(values1).ratingNumber;
        ratings[1] = valueDistributionRating(values2).ratingNumber;
        DNSAnalysisUtils.DNSAnalysisRating dnsAnalysisRating = new DNSAnalysisUtils.DNSAnalysisRating(getLowestValue(ratings));
        return dnsAnalysisRating;
    }

    public static DNSAnalysisUtils.DNSAnalysisRating valueDistributionRating(int[] values) {

        int[] ratings = new int[3];
        ratings[0] = getStandardDeviationRating(values).ratingNumber;
        ratings[1] = getValueRangeBitRating(values).ratingNumber;
        ratings[2] = getDirectionBiasRating(values).ratingNumber;
        DNSAnalysisUtils.DNSAnalysisRating dnsAnalysisRating = new DNSAnalysisUtils.DNSAnalysisRating(getLowestValue(ratings));
        return dnsAnalysisRating;
    }

    public static String[] getPublicDNSResolvers(Interaction[] interactions){
        Set<String> publicDNSResolvers = new LinkedHashSet<String>();
        for (String resolverIP:getResolverIPs(interactions)){
            publicDNSResolvers.add(getPublicDNSResolver(resolverIP));
        }

        return publicDNSResolvers.toArray(String[]::new);
    }
    public static String getPublicDNSResolver(String ipAddress){
        for (String ipRange:googleDNSOutgoingIPRanges) {
            if (new IPAddressString(ipRange).contains(new IPAddressString(ipAddress))){
                return "Google Public DNS";
            }
        }
        for (String ipRange:oneDNSOutgoingIPRanges) {
            if (new IPAddressString(ipRange).contains(new IPAddressString(ipAddress))){
                return "1.1.1.1 (Cloudflare)";
            }
        }

        for (String ipRange:opendnsOutgoingIPRanges) {
            if (new IPAddressString(ipRange).contains(new IPAddressString(ipAddress))){
                return "Cisco OpenDNS";
            }
        }

        for (String ipRange:quad9OutgoingIPRanges) {
            if (new IPAddressString(ipRange).contains(new IPAddressString(ipAddress))){
                return "Quad9 (IBM)";
            }
        }
        return "Unknown";
    }

    public static int getHighestValue(int[] values) {
        return Arrays.stream(values).max().getAsInt();
    }

    public static int getLowestValue(int[] values) {
        return Arrays.stream(values).min().getAsInt();
    }

    public static int[] getUniqueValues(int[] values) {
        return Arrays.stream(values).distinct().toArray();
    }

    public static double standardDeviation(int[] values) {
        double sum = 0.0, standardDeviation = 0.0;
        int length = values.length;

        for (double num : values) {
            sum += num;
        }

        double mean = sum / length;

        for (double num : values) {
            standardDeviation += Math.pow(num - mean, 2);
        }

        return Math.sqrt(standardDeviation / length);
    }

    public static double directionBias(int[] values) {
        double direction = 0;
        double tmpValue = values[0];

        for (int i = 1; i < values.length; i++) {
            if (values[i] > tmpValue) {
                direction += 1;
            } else if (values[i] < tmpValue) {
                direction -= 1;
            }

            tmpValue = values[i];
        }

        return Math.abs(direction) / (values.length - 1);
    }

    public static double valueRangeBits(int[] values) {
        int valueRange = getHighestValue(values) - getLowestValue(values);
        return Math.log(valueRange) / Math.log(2);
    }

    public static DNSAnalysisUtils.DNSAnalysisRating getStandardDeviationRating(int[] values) {
        double standardDeviation = standardDeviation(values);
        if (standardDeviation <= standardDeviationRatings.get(0)) {
            return new DNSAnalysisUtils.DNSAnalysisRating(0);
        } else if (standardDeviation <= standardDeviationRatings.get(1)) {
            return new DNSAnalysisUtils.DNSAnalysisRating(1);
        } else {
            return new DNSAnalysisUtils.DNSAnalysisRating(2);
        }
    }

    public static DNSAnalysisUtils.DNSAnalysisRating getValueRangeBitRating(int[] values) {
        double valueRangeBits = valueRangeBits(values);
        if (valueRangeBits <= valueRangeBitsRatings.get(0)) {
            return new DNSAnalysisUtils.DNSAnalysisRating(0);
        } else if (valueRangeBits <= valueRangeBitsRatings.get(1)) {
            return new DNSAnalysisUtils.DNSAnalysisRating(1);
        } else {
            return new DNSAnalysisUtils.DNSAnalysisRating(2);
        }
    }

    public static DNSAnalysisUtils.DNSAnalysisRating getDirectionBiasRating(int[] values) {
        double directionBias = directionBias(values);
        if (directionBias >= directionBiasRatings.get(0)) {
            return new DNSAnalysisUtils.DNSAnalysisRating(0);
        } else if (directionBias >= directionBiasRatings.get(1)) {
            return new DNSAnalysisUtils.DNSAnalysisRating(1);
        } else {
            return new DNSAnalysisUtils.DNSAnalysisRating(2);
        }
    }

    public static String[] getResolverIPs(Interaction[] interactions) {
        String[] resolverIPs = new String[interactions.length];
        for (int i = 0; i < interactions.length; i++) {
            resolverIPs[i] = interactions[i].clientIp().getHostAddress();
        }

        //return Arrays.stream(resolverIPs).distinct().toArray(String[]::new);
        Set<String> uniqueResolverIPs = new LinkedHashSet<String>( Arrays.asList( resolverIPs ) );
        return uniqueResolverIPs.toArray( new String[uniqueResolverIPs.size()] );
    }

    public static class DNSAnalysisResults {
        DNSAnalysisUtils.DNSAnalysisRating overallRating;
        int totalInteractions;
        DNSAnalysisUtils.DNSAnalysisResults.DNSAnalysisResult[] dnsAnalysisResults;
        DNSAnalysisResults(Interaction[] selectedInteractions) {
            totalInteractions = selectedInteractions.length;
            String[] resolverIPs = getResolverIPs(selectedInteractions);
            dnsAnalysisResults = new DNSAnalysisUtils.DNSAnalysisResults.DNSAnalysisResult[resolverIPs.length + 1];
            Interaction[] tmpInteractions;
            Interaction tmpInteraction;
            DNSAnalysisUtils.DNSAnalysisResults.DNSAnalysisResult tmpDNSAnalysisResult;
            dnsAnalysisResults[0] = new DNSAnalysisUtils.DNSAnalysisResults.DNSAnalysisResult(selectedInteractions, "All Resolver IPs");
            overallRating = dnsAnalysisResults[0].rating;

            for (int i = 0; i < resolverIPs.length; i++) {
                tmpInteractions = new Interaction[0];
                for (int u = 0; u < selectedInteractions.length; u++) {
                    tmpInteraction = selectedInteractions[u];
                    if (tmpInteraction.clientIp().getHostAddress().equals(resolverIPs[i])) {
                        tmpInteractions = Arrays.copyOf(tmpInteractions, tmpInteractions.length + 1);
                        tmpInteractions[tmpInteractions.length - 1] = tmpInteraction;
                    }
                }
                tmpDNSAnalysisResult = new DNSAnalysisUtils.DNSAnalysisResults.DNSAnalysisResult(tmpInteractions, resolverIPs[i]);

                dnsAnalysisResults[i + 1] = tmpDNSAnalysisResult;
                if (tmpDNSAnalysisResult.rating.ratingNumber < overallRating.ratingNumber){
                    overallRating = tmpDNSAnalysisResult.rating;
                }

            }

        }

        public static class DNSAnalysisResult {
            int totalInteractions;
            String resolverIP;
            int totalResolverIPs;
            String[] publicResolvers;

            int[] sourcePorts;
            int[] dnsIds;
            DNSAnalysisUtils.DNSAnalysisResults.DNSAnalysisResult.statisticsResult sourcePortResult;
            DNSAnalysisUtils.DNSAnalysisResults.DNSAnalysisResult.statisticsResult dnsIdResult;
            DNSAnalysisUtils.DNSAnalysisRating rating;

            DNSAnalysisResult(Interaction[] interactions, String resolverIP) {
                this.totalInteractions = interactions.length;
                this.resolverIP = resolverIP;
                totalResolverIPs = getResolverIPs(interactions).length;
                publicResolvers = getPublicDNSResolvers(interactions);
                sourcePorts = new int[interactions.length];
                dnsIds = new int[interactions.length];


                for (int i = 0; i < interactions.length; i++) {
                    sourcePorts[i] = interactions[i].clientPort();
                    dnsIds[i] = Short.toUnsignedInt(ByteBuffer.wrap(interactions[i].dnsDetails().get().query().getBytes()).getShort());
                }

                sourcePortResult = new DNSAnalysisUtils.DNSAnalysisResults.DNSAnalysisResult.statisticsResult(sourcePorts);
                dnsIdResult = new DNSAnalysisUtils.DNSAnalysisResults.DNSAnalysisResult.statisticsResult(dnsIds);

                if (totalInteractions >= minimumRequiredValues) {
                    int[] ratings = new int[2];
                    ratings[0] = sourcePortResult.rating.ratingNumber;
                    ratings[1] = dnsIdResult.rating.ratingNumber;
                    rating = new DNSAnalysisUtils.DNSAnalysisRating(getLowestValue(ratings));
                }else {
                    sourcePortResult.rating = new DNSAnalysisUtils.DNSAnalysisRating(404);
                    dnsIdResult.rating = new DNSAnalysisUtils.DNSAnalysisRating(404);
                    rating = new DNSAnalysisUtils.DNSAnalysisRating(404);
                }

            }

            public static class statisticsResult {
                double standardDeviation;
                double directionBias;
                int uniqueValues;
                int lowestValue;
                int highestValue;
                int difference;
                double valueRangeBits;
                DNSAnalysisUtils.DNSAnalysisRating rating;
                statisticsResult(int[] values) {
                    standardDeviation = standardDeviation(values);
                    directionBias = directionBias(values) * (double)100;
                    uniqueValues = getUniqueValues(values).length;
                    lowestValue = getLowestValue(values);
                    highestValue = getHighestValue(values);
                    difference = getHighestValue(values)- DNSAnalysisUtils.getLowestValue(values);
                    valueRangeBits = valueRangeBits(values);
                    rating = valueDistributionRating(values);
                }
            }
        }
    }
    public static class DNSAnalysisRating {

        String ratingText;
        String ratingColorHex;
        int ratingNumber;
        DNSAnalysisRating(int ratingNumber){
            this.ratingNumber = ratingNumber;
            switch (ratingNumber) {
                case 0:
                    this.ratingText = "POOR";
                    this.ratingColorHex = "ff5353";
                    break;
                case 1:
                    this.ratingText = "GOOD";
                    this.ratingColorHex = "ffff5b";
                    break;
                case 2:
                    this.ratingText = "GREAT";
                    this.ratingColorHex = "7cf487";
                    break;
                default:
                    this.ratingText = "NOT ENOUGH DATA";
                    this.ratingColorHex = "ff5353";
                    break;
            }
        }
    }

    public static final String analysisText = """
                                <h1>Statistics</h1>
                                <h2>General</h2>
                                &emsp;<b>Number of queries: </b> %s<br>
                                &emsp;<b>Number of resolver IPs: </b> %s<br>
                                &emsp;<b>Public resolvers: </b> %s<br>
                                <h2>Source Ports: <b style="color: #%s;">%s</b></h2>
                                &emsp;<b>Standard deviation: </b>%.2f<br>
                                &emsp;<b>Direction bias: </b>%.2f%%<br>
                                &emsp;<b>Unique source ports: </b>%s out of %s<br>
                                &emsp;<b>Lowest port: </b>%s<br>
                                &emsp;<b>Highest port: </b>%s<br>
                                &emsp;<b>Port difference: </b>%s<br>
                                &emsp;<b>Port difference (bits): </b>%.2f<br>                               
                                <h2>DNS IDs: <b style="color: #%s;">%s</b></h2>
                                &emsp;<b>Standard deviation: </b>%.2f<br>
                                &emsp;<b>Direction bias: </b>%.2f%%<br>
                                &emsp;<b>Unique DNS IDs: </b>%s out of %s<br>
                                &emsp;<b>Lowest ID: </b>%s<br>
                                &emsp;<b>Highest ID: </b>%s<br>
                                &emsp;<b>ID difference: </b>%s<br>
                                &emsp;<b>ID difference (bits): </b>%.2f<br> 
                                """;

    public static final String helpText = """
                    <html>
                    <h1>DNS Analyzer</h1>
                    <i>A Burp extension for discovering DNS vulnerabilities in web applications!</i>
                    <h2>Howto</h2>
                    You can find an in-depth guide <a href="https://sec-consult.com/blog/detail/dns-analyzer-finding-dns-vulnerabilities-with-burp-suite/">here</a>, which boils down to the following steps:
                    <ol>
                    <li>Click "Copy to Clipboard" to generate and copy a Burp Collaborator domain</li>
                    <li>Get something to resolve the generated domain via DNS. For example, by using it:</li>
                    <ul>
                    <li>as an e-mail domain (e.g., test@[collaborator domain])</li>
                    <ul>
                    <li>Use it at registrations</li>
                    <li>Use it at password resets</li>
                    <li>Use it for news-letters</li>
                    <li>...</li>
                    </ul>
                    <li>via SSRF</li>
                    <li>anywhere, where the collaborator domain gets resolved via DNS</li>
                    </ul>
                    <li>Analyze the DNS name resolution by selecting DNS interactions in the table</li>
                    <li>...</li>
                    <li>Profit</li>
                    </ol>
                    <h2>The Table</h2>
                    The table holds general and DNS-specific information of the Collaborator interactions from step 2 of the Howto, such as:
                    <ol>
                    <li><b>#: </b>The message number</li>
                    <li><b>Collaborator ID: </b>The used Collaborator prefix</li>
                    <li><b>Resolver IP: </b>The egress IP of the resolver that sent a DNS query to the Collaborator server</li>
                    <li><b>Source Port: </b>UDP source port of the DNS query</li>
                    <li><b>DNS ID: </b>DNS ID of the UDP DNS query</li>
                    <li><b>Query Type: </b>Query type of the DNS query</li>
                    <li><b>Public Resolver: </b>Indicates if the DNS query was sent by a large public resolver (Google Public DNS, oneDNS (Cloudflare), openDNS (Cisco), quad9 (IBM et al.))</li>
                    <li><b>Timestamp: </b>A timestamp</li>
                    </ol>
                    <h2>Kaminsky Status</h2>
                    So, what's the DNS Analyzer doing and what's up with the "Kaminsky Status"?<br>
                    By selecting more than %s DNS messages from the table, the DNS Analyzer calculates and evaluates the following 3 values:<br>
                    <ul>
                    <li><b>Standard deviation:</b> Checks for a low standard deviation in source port and DNS ID distributions.</li>
                    <b style="color: #ff5353">POOR</b>: 0 - 296<br>
                    <b style="color: #ffff5b">GOOD</b>: 296 - 3980<br>
                    <b style="color: #7cf487">GREAT</b>: 3980 - 20000+<br>
                    <li><b>Direction Bias:</b> Checks if source port and DNS ID distributions are biased in an upward or downward direction.</li>
                    <b style="color: #ff5353">POOR</b>: 80%% - 100%%<br>
                    <b style="color: #ffff5b">GOOD</b>: 50%% - 80%%<br>
                    <b style="color: #7cf487">GREAT</b>: 0%% - 20%%<br>
                    <li><b>Port difference (bits):</b> Checks the differences of the lowest and the highest ports and DNS IDs in bits.</li>
                    <b style="color: #ff5353">POOR</b>: 0 - 10 bits<br>
                    <b style="color: #ffff5b">GOOD</b>: 10 - 13.75 bits<br>
                    <b style="color: #7cf487">GREAT</b>: 13.75 - 16 bits<br>
                    </ul>
                    These metrics are a mixture of the metrics from <a href="https://www.dns-oarc.net/oarc/services/porttest">DNS-OARC</a> and the <a href="https://www.grc.com/dns/dns.htm">Gibson Research Corporation (GRC)</a>.<br>
                    Essentially, we're analysing if the distributions of UDP source ports and DNS IDs are guessable and if a Kaminsky attack is potentially possible.<br>
                    This analysis is done for DNS messages of all selected resolver IPs at once ("All Resolver IPs") and also for DNS messages of each individual resolver IP. This is important to see differences in value distributions between used resolvers.<br>
                    If there are less than %<s DNS messages for a specific resolver, then no analysis is possible, which is indicated with <b style="color: #ff5353">NOT ENOUGH DATA</b>.<br>
                    Furthermore, the DNS Analyzer always chooses the worst/lowest metric for the Kaminsky status.<br>
                    <h2>Bug Bounty Tips</h2>
                    Should you be looking for DNS vulnerabilities in bug bounty domains?<br>
                    YES! However, only report a DNS vulnerability if:
                    <ol>
                    <li>infrastructure is in the scope of the bug bounty program</li>
                    <li>you've confirmed the vulnerability via in-depth DNS analysis (e.g., via the <a href="https://github.com/The-Login/DNS-Analysis-Server">DNS Analysis Server</a>)</li>
                    </ol>
                    Essentially, <b>don't flood bug bounty programs with DNS vulnerability reports without doing proper research first!</b>
                    <h2>Further Info</h2>
                    As already mentioned, you can find a full DNS Analyzer guide <a href="https://sec-consult.com/blog/detail/dns-analyzer-finding-dns-vulnerabilities-with-burp-suite/">here</a>.<br>
                    Also, you can find further information about DNS analysis and DNS vulnerabilities in the following blog posts:
                    <ul>
                    <li><a href="https://sec-consult.com/blog/detail/forgot-password-taking-over-user-accounts-kaminsky-style/">First blog post</a> showing the basics of DNS analysis in web applications</li>
                    <li><a href="https://sec-consult.com/blog/detail/melting-the-dns-iceberg-taking-over-your-infrastructure-kaminsky-style/">Second blog post</a> showing further DNS analysis methods and exploitation</li>
                    </ul>
                    Moreover, the Collaborator server has its limits. For in-depth DNS analysis you can use the <a href="https://github.com/The-Login/DNS-Analysis-Server">DNS Analysis Server</a>.
                    </html>
                    """;

}
