using System;
using System.Collections.Generic;

/// <summary>
/// CVEのAPIからダウンロードしたJSONデータのデシリアライズ用クラス。
/// 以下の手順で作成。
/// １．http://json2csharp.com/ からAPIのJSONデータをC#のクラスへ自動変換
/// ２．別個のクラスとして作成されたネスト部位を、RootObjectの内部クラスへ移動
/// ３．RootObjectをSecurityGuidanceへ改名
/// </summary>
namespace CVESummaryGenerator
{
    class SecurityGuidance
    {
        public class AffectedProduct
        {
            public string Name { get; set; }
            public object Platform { get; set; }
            public int ImpactId { get; set; }
            public string Impact { get; set; }
            public int SeverityId { get; set; }
            public string Severity { get; set; }
            public double BaseScore { get; set; }
            public double TemporalScore { get; set; }
            public double EnvironmentScore { get; set; }
            public string VectorString { get; set; }
            public object Supersedence { get; set; }
            public object KnowledgeBaseId { get; set; }
            public object KnowledgeBaseUrl { get; set; }
            public object MonthlyKnowledgeBaseId { get; set; }
            public object MonthlyKnowledgeBaseUrl { get; set; }
            public object DownloadUrl { get; set; }
            public object DownloadTitle { get; set; }
            public object MonthlyDownloadUrl { get; set; }
            public object MonthlyDownloadTitle { get; set; }
            public string ArticleTitle1 { get; set; }
            public string ArticleUrl1 { get; set; }
            public string DownloadTitle1 { get; set; }
            public string DownloadUrl1 { get; set; }
            public bool DoesRowOneHaveAtLeastOneArticleOrUrl { get; set; }
            public string ArticleTitle2 { get; set; }
            public object ArticleUrl2 { get; set; }
            public string DownloadTitle2 { get; set; }
            public object DownloadUrl2 { get; set; }
            public bool DoesRowTwoHaveAtLeastOneArticleOrUrl { get; set; }
            public string ArticleTitle3 { get; set; }
            public object ArticleUrl3 { get; set; }
            public string DownloadTitle3 { get; set; }
            public object DownloadUrl3 { get; set; }
            public bool DoesRowThreeHaveAtLeastOneArticleOrUrl { get; set; }
            public string ArticleTitle4 { get; set; }
            public object ArticleUrl4 { get; set; }
            public string DownloadTitle4 { get; set; }
            public object DownloadUrl4 { get; set; }
            public bool DoesRowFourHaveAtLeastOneArticleOrUrl { get; set; }
            public int CountOfRowsWithAtLeastOneArticleOrUrl { get; set; }
        }

        public class Revision
        {
            public string Version { get; set; }
            public DateTime Date { get; set; }
            public string Description { get; set; }
        }

        public class ExploitabilityAssessment
        {
            public class LatestReleaseExploitability
            {
                public int Id { get; set; }
                public string Name { get; set; }
            }

            public class OlderReleaseExploitability
            {
                public int Id { get; set; }
                public string Name { get; set; }
            }

            public object DenialOfServiceExploitability { get; set; }
        }

        public DateTime PublishedDate { get; set; }
        public string CveNumber { get; set; }
        public List<AffectedProduct> AffectedProducts { get; set; }
        public string CveTitle { get; set; }
        public string Description { get; set; }
        public List<object> Workarounds { get; set; }
        public List<object> Mitigations { get; set; }
        public List<object> Acknowledgments { get; set; }
        public string Disclaimer { get; set; }
        public List<Revision> Revisions { get; set; }
        public string FrequentlyAskedQuestions { get; set; }
        public string PubliclyDisclosed { get; set; }
        public string Exploited { get; set; }
    }
}
