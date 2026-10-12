// Brands that scammers most often impersonate to older users, with the domains
// each brand really uses. `keywords` are matched as whole tokens in hostnames
// and as whole words in page titles / site names / logo text. Brands whose
// name is an ordinary word ("Apple", "Chase") list `phrases` to look for in
// page text instead.

export const BRANDS = [
  { name: 'PayPal', keywords: ['paypal'], domains: ['paypal.com', 'paypal.me', 'paypalobjects.com'] },
  { name: 'Amazon', keywords: ['amazon'], domains: ['amazon.com', 'amazon.co.uk', 'amazon.ca', 'amazon.de', 'amazon.fr', 'amazon.it', 'amazon.es', 'amazon.co.jp', 'amazon.in', 'amazon.com.au', 'amazon.com.mx', 'amazon.com.br', 'amazon.dev', 'media-amazon.com', 'primevideo.com', 'a2z.com'] },
  { name: 'Apple', keywords: ['apple', 'icloud', 'itunes', 'appleid'], domains: ['apple.com', 'icloud.com', 'me.com', 'mzstatic.com', 'apple.news'], phrases: ['Apple ID', 'Apple Account', 'Apple Support', 'Apple Pay'] },
  { name: 'Microsoft', keywords: ['microsoft', 'outlook', 'office365', 'hotmail', 'windows', 'msn', 'onedrive'], domains: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com', 'hotmail.com', 'msn.com', 'windows.com', 'microsoftonline.com', 'onedrive.com', 'bing.com', 'skype.com', 'xbox.com', 'azure.com'], phrases: ['Microsoft account', 'Microsoft 365', 'Office 365', 'Outlook Web', 'Windows Defender', 'Windows Security'] },
  { name: 'Google', keywords: ['google', 'gmail'], domains: ['google.com', 'gmail.com', 'youtube.com', 'gstatic.com', 'google.co.uk', 'google.ca', 'google.co.il'] },
  { name: 'Facebook', keywords: ['facebook', 'meta'], domains: ['facebook.com', 'fb.com', 'meta.com', 'messenger.com', 'fbcdn.net'], phrases: ['Meta Business', 'Meta for Business', 'Meta Verified'] },
  { name: 'Instagram', keywords: ['instagram'], domains: ['instagram.com', 'cdninstagram.com'] },
  { name: 'WhatsApp', keywords: ['whatsapp'], domains: ['whatsapp.com', 'whatsapp.net', 'wa.me'] },
  { name: 'Netflix', keywords: ['netflix'], domains: ['netflix.com', 'nflxext.com', 'nflximg.net'] },
  { name: 'Bank of America', keywords: ['bankofamerica', 'bofa'], domains: ['bankofamerica.com', 'bofa.com', 'mbna.com'] },
  { name: 'Chase', keywords: ['chase', 'jpmorgan'], domains: ['chase.com', 'jpmorgan.com', 'jpmorganchase.com'], phrases: ['Chase Bank', 'Chase Online', 'Chase Sapphire', 'Chase Freedom'] },
  { name: 'Wells Fargo', keywords: ['wellsfargo'], domains: ['wellsfargo.com', 'wf.com'] },
  { name: 'Citibank', keywords: ['citi', 'citibank'], domains: ['citi.com', 'citibank.com', 'citigroup.com'], phrases: ['Citi Card', 'Citi Online', 'Citi Bank'] },
  { name: 'Capital One', keywords: ['capitalone'], domains: ['capitalone.com'] },
  { name: 'U.S. Bank', keywords: ['usbank'], domains: ['usbank.com'] },
  { name: 'PNC', keywords: ['pnc'], domains: ['pnc.com'] },
  { name: 'American Express', keywords: ['amex', 'americanexpress'], domains: ['americanexpress.com', 'aexp.com'] },
  { name: 'Discover', keywords: ['discover'], domains: ['discover.com'], phrases: ['Discover Card', 'Discover Bank', 'Discover It'] },
  { name: 'Venmo', keywords: ['venmo'], domains: ['venmo.com'] },
  { name: 'Zelle', keywords: ['zelle'], domains: ['zellepay.com', 'zelle.com'] },
  { name: 'Cash App', keywords: ['cashapp'], domains: ['cash.app', 'cashapp.com', 'squareup.com'] },
  { name: 'Coinbase', keywords: ['coinbase'], domains: ['coinbase.com'] },
  { name: 'eBay', keywords: ['ebay'], domains: ['ebay.com', 'ebay.co.uk', 'ebay.ca', 'ebayimg.com'] },
  { name: 'Walmart', keywords: ['walmart'], domains: ['walmart.com', 'walmartimages.com'] },
  { name: 'Costco', keywords: ['costco'], domains: ['costco.com'] },
  { name: 'Best Buy / Geek Squad', keywords: ['bestbuy', 'geeksquad'], domains: ['bestbuy.com', 'geeksquad.com'] },
  { name: 'USPS', keywords: ['usps'], domains: ['usps.com', 'usps.gov'] },
  { name: 'UPS', keywords: ['ups'], domains: ['ups.com'] },
  { name: 'FedEx', keywords: ['fedex'], domains: ['fedex.com'] },
  { name: 'DHL', keywords: ['dhl'], domains: ['dhl.com', 'dhl.de'] },
  { name: 'IRS', keywords: ['irs'], domains: ['irs.gov'] },
  { name: 'Social Security', keywords: ['ssa', 'socialsecurity'], domains: ['ssa.gov', 'socialsecurity.gov'] },
  { name: 'Medicare', keywords: ['medicare'], domains: ['medicare.gov', 'cms.gov'] },
  { name: 'AT&T', keywords: ['att'], domains: ['att.com', 'att.net'] },
  { name: 'Verizon', keywords: ['verizon'], domains: ['verizon.com', 'verizonwireless.com', 'vzw.com'] },
  { name: 'Xfinity', keywords: ['xfinity', 'comcast'], domains: ['xfinity.com', 'comcast.com', 'comcast.net'] },
  { name: 'Spectrum', keywords: ['spectrum'], domains: ['spectrum.com', 'spectrum.net', 'charter.com'], phrases: ['Spectrum Internet', 'Spectrum Mobile', 'Charter Spectrum', 'My Spectrum'] },
  { name: 'Norton', keywords: ['norton', 'nortonlifelock'], domains: ['norton.com', 'nortonlifelock.com', 'gen.digital'] },
  { name: 'McAfee', keywords: ['mcafee'], domains: ['mcafee.com'] },
  { name: 'Yahoo', keywords: ['yahoo'], domains: ['yahoo.com', 'yimg.com'] },
  { name: 'AOL', keywords: ['aol'], domains: ['aol.com'] },
  { name: 'DocuSign', keywords: ['docusign'], domains: ['docusign.com', 'docusign.net'] },
  { name: 'Dropbox', keywords: ['dropbox'], domains: ['dropbox.com'] },
  { name: 'LinkedIn', keywords: ['linkedin'], domains: ['linkedin.com', 'licdn.com'] },
];

/** Every domain owned by a listed brand. */
export function allBrandDomains() {
  return BRANDS.flatMap((b) => b.domains);
}
