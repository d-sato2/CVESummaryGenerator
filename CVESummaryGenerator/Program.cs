using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;
using System.Xml.Linq;
using Newtonsoft.Json;

namespace CVESummaryGenerator
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
            Console.ReadLine();
            string WIN2008 = "Windows Server 2008 for 32-bit Systems Service Pack 2";
            string WIN2012 = "Windows Server 2012 R2 (Server Core installation)";
            string WIN2016 = "Windows Server 2016  (Server Core installation)";
            var wc = new WebClient();
            wc.Encoding = Encoding.UTF8;

            // TODO:取得するCVE一覧を取得

            // TODO:CVE一覧から取得するCVEを一つずつ取得
            var cve = "CVE-2018-8308";

            // TODO:正規表現で正しいCVEかチェックする
            // (CVE - 20[0 - 9][0 - 9] -\d{ 4}|ADV\d{ 6})

            if (Regex.IsMatch(cve, @"(CVE-20[0-9][0-9]-\d{4}|ADV\d{6})"))
            {
                Console.WriteLine("正規表現と一致します");
            }
            else
            {
                Console.WriteLine("一致しません");
            }

            // APIからjson形式の文字列を取得
            var jsonString = wc.DownloadString(@"https://portal.msrc.microsoft.com/api/security-guidance/ja-JP/CVE/" + cve);

            // ダウンロードしたjson文字列を出力
            Console.WriteLine(jsonString);

            // json形式にシリアライズ
            RootObject json = JsonConvert.DeserializeObject<RootObject>(jsonString);

            //まとめ作成
            //全製品共通項目
            Console.WriteLine("CVE:{0}", cve);
            Console.WriteLine("概要:{0}", json.cveTitle);
            Console.WriteLine("詳細:{0}", json.description.Replace("\n", ""));
            Console.WriteLine("一般に公開:{0}", json.publiclyDisclosed); // 一般に公開
            Console.WriteLine("悪用:{0}", json.exploited); // 悪用
            Console.WriteLine("最新のソフトウェア リリース:{0}-{1}"
                                , json.exploitabilityAssessment.latestReleaseExploitability.id
                                , json.exploitabilityAssessment.latestReleaseExploitability.name); // 最新のソフトウェア リリース
            Console.WriteLine("過去のソフトウェア リリース:{0}-{1}"
                                , json.exploitabilityAssessment.olderReleaseExploitability.id
                                , json.exploitabilityAssessment.olderReleaseExploitability.name); // 過去のソフトウェア リリース

            // TODO：「サービス拒否」の項目はjsonにないのか確認

            //各製品共通項目
            // json.affectedProducts.ForEach(n => Console.WriteLine("name:{0}, vectorstring:{1}", n.name, n.vectorString));
            var targetProducts = json.affectedProducts.Where(n => n.name == WIN2008 || n.name == WIN2012 || n.name == WIN2016);
            var listCVSS = new List<string>();
            var listbaseScore = new List<double>();
            var listtemporalScore = new List<double>();
            var listseverity = new List<string>();
            AffectedProduct summaryOfTargetProducts = new AffectedProduct();
            bool isFirst = true;
            string containsWIN2008 = "☓";
            string containsWIN2012 = "☓";
            string containsWIN2016 = "☓";
            foreach (var product in targetProducts)
            {
                if (isFirst)
                {
                    summaryOfTargetProducts = product;
                    isFirst = false;
                }

                if (product.name == WIN2008) { containsWIN2008 = "○"; }
                if (product.name == WIN2012) { containsWIN2012 = "○"; }
                if (product.name == WIN2016) { containsWIN2016 = "○"; }

                if (summaryOfTargetProducts.vectorString == null)
                {
                    summaryOfTargetProducts.vectorString = product.vectorString;
                }
                else if (!summaryOfTargetProducts.vectorString.Equals(product.vectorString))
                {
                    summaryOfTargetProducts.vectorString = "vectorStringの中に一致しないものがあります";
                }
                Console.WriteLine(summaryOfTargetProducts.vectorString);

                if (!summaryOfTargetProducts.baseScore.Equals(product.baseScore))
                {
                    summaryOfTargetProducts.baseScore = 0;
                    Console.WriteLine("baseScoreの中に一致しないものがあります");
                }
                Console.WriteLine(summaryOfTargetProducts.baseScore);

                if (!summaryOfTargetProducts.temporalScore.Equals(product.temporalScore))
                {
                    summaryOfTargetProducts.temporalScore = 0;
                    Console.WriteLine("temporalScoreの中に一致しないものがあります");
                }
                Console.WriteLine(summaryOfTargetProducts.temporalScore);

                if (!summaryOfTargetProducts.severity.Equals(product.severity))
                {
                    summaryOfTargetProducts.severity = "severityの中に一致しないものがあります";
                    Console.WriteLine("severityの中に一致しないものがあります");
                }
                Console.WriteLine(summaryOfTargetProducts.severity);
            }
            Console.WriteLine(isFirst);
            Console.WriteLine(summaryOfTargetProducts.vectorString);
            Console.WriteLine(summaryOfTargetProducts.baseScore);
            Console.WriteLine(summaryOfTargetProducts.temporalScore);
            Console.WriteLine(summaryOfTargetProducts.severity);
            Console.WriteLine(WIN2008 + ":" + containsWIN2008);
            Console.WriteLine(WIN2012 + ":" + containsWIN2012);
            Console.WriteLine(WIN2016 + ":" + containsWIN2016);

        }
    }
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

    public class RootObject
    {
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
