using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DU_Market_Release
{
    internal class MarketData
    {
    }
    public class MarketString
    {
        
        public int marketId { get; set; }
        public long orderid { get; set; }
        public long itemtyp { get; set; }
        public long quantity { get; set; }
        public DateTime expirationDate { get; set; }
        public DateTime updatedate { get; set; }
        public decimal price { get; set; }
        public DateTime date { get; set; }

    }
    public class jksonMarketString
    {
        public int marketId { get; set; }
        public long orderId { get; set; }
        public long itemType { get; set; }
        public long buyQuantity { get; set; }
        public DateTime expirationDate { get; set; }
        public DateTime updateDate { get; set; }
        public decimal amount { get; set; }

    }
    public class Discord_login_data
    {
        public string access_token { get; set; }
        public DateTime expires_date { get; set; }
    }
    public class Discord_Access_response
    {
        public string access_token { get; set; }
        public string expires_in { get; set; }
    }
    public class Market_Average
    {
        public long itemtyp { get; set; }
        public decimal averagebuyPrice { get; set; }
        public decimal averagesellPrice { get; set; }
        public decimal maxsellPrice { get; set; }
        public decimal minsellPrice { get; set; }
        public decimal maxbuyPrice { get; set; }
        public decimal minbuyPrice { get; set; }
        public DateTime Actdate { get; set; }

    }
}
