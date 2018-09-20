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

            // JSONを.NETのクラスにデシリアライズ
            SecurityGuidance sg = JsonConvert.DeserializeObject<SecurityGuidance>(jsonString);

            //まとめ作成
            //全製品共通項目
            Console.WriteLine("CVE:{0}", cve);
            Console.WriteLine("概要:{0}", sg.cveTitle);
            Console.WriteLine("詳細:{0}", sg.description.Replace("\n", ""));
            Console.WriteLine("一般に公開:{0}", sg.publiclyDisclosed); // 一般に公開
            Console.WriteLine("悪用:{0}", sg.exploited); // 悪用
            Console.WriteLine("最新のソフトウェア リリース:{0}-{1}"
                                , sg.exploitabilityAssessment.latestReleaseExploitability.id
                                , sg.exploitabilityAssessment.latestReleaseExploitability.name); // 最新のソフトウェア リリース
            Console.WriteLine("過去のソフトウェア リリース:{0}-{1}"
                                , sg.exploitabilityAssessment.olderReleaseExploitability.id
                                , sg.exploitabilityAssessment.olderReleaseExploitability.name); // 過去のソフトウェア リリース

            // TODO：「サービス拒否」の項目はjsonにないのか確認

            //各製品共通項目
            // sg.affectedProducts.ForEach(n => Console.WriteLine("name:{0}, vectorstring:{1}", n.name, n.vectorString));
            var targetProducts = sg.affectedProducts.Where(n => n.name == WIN2008 || n.name == WIN2012 || n.name == WIN2016);
            var listCVSS = new List<string>();
            var listbaseScore = new List<double>();
            var listtemporalScore = new List<double>();
            var listseverity = new List<string>();
            SecurityGuidance.AffectedProduct summaryOfTargetProducts = new SecurityGuidance.AffectedProduct();
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
}
