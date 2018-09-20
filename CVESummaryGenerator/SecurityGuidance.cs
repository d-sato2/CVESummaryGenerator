using System;
using System.Collections.Generic;
using System.Text;

namespace CVESummaryGenerator
{
    class SecurityGuidance
    {
        public class AffectedProduct
        {
            public string name { get; set; }
            public object platform { get; set; }
            public int impactId { get; set; }
            public string impact { get; set; }
            public int severityId { get; set; }
            public string severity { get; set; }
            public double baseScore { get; set; }
            public double temporalScore { get; set; }
            public double environmentScore { get; set; }
            public string vectorString { get; set; }
            public object supersedence { get; set; }
            public object knowledgeBaseId { get; set; }
            public object knowledgeBaseUrl { get; set; }
            public object monthlyKnowledgeBaseId { get; set; }
            public object monthlyKnowledgeBaseUrl { get; set; }
            public object downloadUrl { get; set; }
            public object downloadTitle { get; set; }
            public object monthlyDownloadUrl { get; set; }
            public object monthlyDownloadTitle { get; set; }
            public string articleTitle1 { get; set; }
            public string articleUrl1 { get; set; }
            public string downloadTitle1 { get; set; }
            public string downloadUrl1 { get; set; }
            public bool doesRowOneHaveAtLeastOneArticleOrUrl { get; set; }
            public string articleTitle2 { get; set; }
            public object articleUrl2 { get; set; }
            public string downloadTitle2 { get; set; }
            public object downloadUrl2 { get; set; }
            public bool doesRowTwoHaveAtLeastOneArticleOrUrl { get; set; }
            public string articleTitle3 { get; set; }
            public object articleUrl3 { get; set; }
            public string downloadTitle3 { get; set; }
            public object downloadUrl3 { get; set; }
            public bool doesRowThreeHaveAtLeastOneArticleOrUrl { get; set; }
            public string articleTitle4 { get; set; }
            public object articleUrl4 { get; set; }
            public string downloadTitle4 { get; set; }
            public object downloadUrl4 { get; set; }
            public bool doesRowFourHaveAtLeastOneArticleOrUrl { get; set; }
            public int countOfRowsWithAtLeastOneArticleOrUrl { get; set; }
        }

        public class Revision
        {
            public string version { get; set; }
            public DateTime date { get; set; }
            public string description { get; set; }
        }

        public class LatestReleaseExploitability
        {
            public int id { get; set; }
            public string name { get; set; }
        }

        public class OlderReleaseExploitability
        {
            public int id { get; set; }
            public string name { get; set; }
        }

        public class ExploitabilityAssessment
        {
            public LatestReleaseExploitability latestReleaseExploitability { get; set; }
            public OlderReleaseExploitability olderReleaseExploitability { get; set; }
            public object denialOfServiceExploitability { get; set; }
        }

        public DateTime publishedDate { get; set; }
        public string cveNumber { get; set; }
        public List<AffectedProduct> affectedProducts { get; set; }
        public string cveTitle { get; set; }
        public string description { get; set; }
        public List<object> workarounds { get; set; }
        public List<object> mitigations { get; set; }
        public List<object> acknowledgments { get; set; }
        public string disclaimer { get; set; }
        public List<Revision> revisions { get; set; }
        public string frequentlyAskedQuestions { get; set; }
        public ExploitabilityAssessment exploitabilityAssessment { get; set; }
        public string publiclyDisclosed { get; set; }
        public string exploited { get; set; }
    }
}
