﻿using System;
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
            Console.WriteLine("概要:{0}", sg.CveTitle);
            Console.WriteLine("詳細:{0}", sg.Description.Replace("\n", ""));
            Console.WriteLine("一般に公開:{0}", sg.PubliclyDisclosed); // 一般に公開
            Console.WriteLine("悪用:{0}", sg.Exploited); // 悪用
            Console.WriteLine("最新のソフトウェア リリース:{0}-{1}"
                                , sg.ExploitabilityAssessment.LatestReleaseExploitability.Id
                                , sg.ExploitabilityAssessment.LatestReleaseExploitability.Name); // 最新のソフトウェア リリース
            Console.WriteLine("過去のソフトウェア リリース:{0}-{1}"
                                , sg.ExploitabilityAssessment.OlderReleaseExploitability.Id
                                , sg.ExploitabilityAssessment.OlderReleaseExploitability.Name); // 過去のソフトウェア リリース

            // TODO：「サービス拒否」の項目はjsonにないのか確認

            //各製品共通項目
            // sg.affectedProducts.ForEach(n => Console.WriteLine("name:{0}, vectorstring:{1}", n.name, n.vectorString));
            var targetProducts = sg.AffectedProducts.Where(n => n.Name == WIN2008 || n.Name == WIN2012 || n.Name == WIN2016);
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

                if (product.Name == WIN2008) { containsWIN2008 = "○"; }
                if (product.Name == WIN2012) { containsWIN2012 = "○"; }
                if (product.Name == WIN2016) { containsWIN2016 = "○"; }

                if (summaryOfTargetProducts.VectorString == null)
                {
                    summaryOfTargetProducts.VectorString = product.VectorString;
                }
                else if (!summaryOfTargetProducts.VectorString.Equals(product.VectorString))
                {
                    summaryOfTargetProducts.VectorString = "vectorStringの中に一致しないものがあります";
                }
                Console.WriteLine(summaryOfTargetProducts.VectorString);

                if (!summaryOfTargetProducts.BaseScore.Equals(product.BaseScore))
                {
                    summaryOfTargetProducts.BaseScore = 0;
                    Console.WriteLine("baseScoreの中に一致しないものがあります");
                }
                Console.WriteLine(summaryOfTargetProducts.BaseScore);

                if (!summaryOfTargetProducts.TemporalScore.Equals(product.TemporalScore))
                {
                    summaryOfTargetProducts.TemporalScore = 0;
                    Console.WriteLine("temporalScoreの中に一致しないものがあります");
                }
                Console.WriteLine(summaryOfTargetProducts.TemporalScore);

                if (!summaryOfTargetProducts.Severity.Equals(product.Severity))
                {
                    summaryOfTargetProducts.Severity = "severityの中に一致しないものがあります";
                    Console.WriteLine("severityの中に一致しないものがあります");
                }
                Console.WriteLine(summaryOfTargetProducts.Severity);
            }
            Console.WriteLine(isFirst);
            Console.WriteLine(summaryOfTargetProducts.VectorString);
            Console.WriteLine(summaryOfTargetProducts.BaseScore);
            Console.WriteLine(summaryOfTargetProducts.TemporalScore);
            Console.WriteLine(summaryOfTargetProducts.Severity);
            Console.WriteLine(WIN2008 + ":" + containsWIN2008);
            Console.WriteLine(WIN2012 + ":" + containsWIN2012);
            Console.WriteLine(WIN2016 + ":" + containsWIN2016);
            Console.ReadLine();

        }
    }
}
