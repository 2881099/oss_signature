using System;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using Newtonsoft.Json;

namespace c_run
{
    class Program
    {
        static void Main(string[] args)
        {
            var id = "6MKOqxGiGU4AUk44";
            var key = "ufu7nS8kS59awNihtjSonMETLI0KLy";
            var host = "http://post-test.oss-cn-hangzhou.aliyuncs.com";

            var now = DateTime.UtcNow;
			var end = now.AddSeconds(30);
			var expiration = end.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");

			var dir = "user-dir/";

			var conditions = new List<object>();
			//最大文件大小.用户可以自己设置
			conditions.Add(new object[] { "content-length-range", 0, 1048576000 });
			//表示用户上传的数据,必须是以$dir开始, 不然上传会失败,这一步不是必须项,只是为了安全起见,防止用户通过policy上传到别人的目录
			conditions.Add(new object[] { "starts-with", "$key", dir });

			var arr = new Hashtable();
			arr["expiration"] = expiration;
			arr["conditions"] = conditions;

			var policy = JsonConvert.SerializeObject(arr);
			var base64_policy = Convert.ToBase64String(Encoding.UTF8.GetBytes(policy));
			var string_to_sign = base64_policy;
			var signature = Convert.ToBase64String((byte[])Hash_HMAC(string_to_sign, key, true));

            Console.WriteLine(JsonConvert.SerializeObject(new {
                accessid = id,
                host = host,
                policy = base64_policy,
                signature = signature,
                expire = end,
                dir = dir
            }));
        }

        public static object Hash_HMAC(string signatureString, string secretKey, bool raw_output = false) {
            HMACSHA1 hmac = new HMACSHA1(Encoding.UTF8.GetBytes(secretKey));
            hmac.Initialize();
            byte[] buffer = Encoding.UTF8.GetBytes(signatureString);
            if (raw_output) return hmac.ComputeHash(buffer);
            return BitConverter.ToString(hmac.ComputeHash(buffer)).Replace("-", "").ToLower();
        }
    }
}
