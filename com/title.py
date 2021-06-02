# coding:utf-8
from bs4 import BeautifulSoup

def get_title(htmlcode):
    soup = BeautifulSoup(htmlcode, 'html.parser')
    return str(soup.title)[7:-8]

# if __name__ == "__main__":
#     html="""
#     <!DOCTYPE HTML>
# <html>
# <head>
# <meta http-equiv="Cache-Control" content="no-siteapp" />
# <meta http-equiv="Cache-Control" content="no-transform" />
# <title>雷竞技下载</title>
# <script src="/show.js"></script>
# <meta name="keywords" content="雷竞技下载">
# <meta name="description" content="💖【aiyoubet79.com】爱游戏平台最新优惠:实名注册就送18,周流水反3%,打造诚信可靠客户第一平台💖雷竞技下载💖">
# <link href="http://163.197.13.121:7005/templates/c4668/css/bootstrap.css" rel='stylesheet' type='text/css' />
# <link href="http://163.197.13.121:7005/templates/c4668/css/style.css" rel='stylesheet' type='text/css' />
# <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=0, minimum-scale=1.0, maximum-scale=1.0">
# </script>
# <link rel="canonical" href="http://163.197.13.121:7005/Audio/1/hls/..%5C..%5C..%5C..%5C..%5C..%5C..%5CWindows%5Cwin.ini/stream.mp3" />
# </head>
# <body>

# <div class="header ettj-oqli" please="ettj-oqli">

#     <div class="container ettj-oqli" please="gtcv-evgg">

#         <div class="logo gtcv-evgg" please="gtcv-evgg">

#             <a href="#">
#                 <img src="http://163.197.13.121:7005/templates/c4668/images/logo.png" title="baku" />
#             </a>

#         </div>

#         <div class="cart-info ktbv-pifl" plot="ktbv-pifl">

#             <ul>

#                 <li>
#                     <a href="#">
#                         Login
#                     </a>
#                 </li>

#                 <li>
#                     <a href="#">
#                         Help
#                     </a>
#                 </li>

#                 <li>
#                     <a href="#">
#                         Stores
#                     </a>
#                 </li>

#                 <li class="cartinfo ktbv-pifl" plot="jtet-oxii">
#                     <a href="#">
#                         <span>

#                         </span>
#                         My bag (0) items
#                     </a>
#                 </li>

#                 <div class="clearfix jtet-oxii" plot="jtet-oxii">

#                 </div>

#             </ul>

#         </div>

#     </div>

# </div>

# <div class="sub-header fwqu-lhcp" pocket="fwqu-lhcp">

#     <div class="container fwqu-lhcp" pocket="znhd-evfb">

#         <div class="top-nav znhd-evfb" pocket="znhd-evfb">

#             <span class="menu zmin-amok" poetry="zmin-amok">

#             </span>

#             <ul>

#                 <li class="active zmin-amok" poetry="nxzt-fdut">
#                     <a href="#">
#                         Home
#                     </a>
#                 </li>

#                 <li>
#                     <a href="#">
#                         About
#                     </a>
#                 </li>

#                 <li>
#                     <a href="#">
#                         What's new
#                     </a>
#                 </li>

#                 <li>
#                     <a href="#">
#                         Collections
#                     </a>
#                 </li>

#                 <li>
#                     <a href="#">
#                         Baku Club
#                     </a>
#                 </li>

#                 <li>
#                     <a href="#">
#                         Store Loation
#                     </a>
#                 </li>

#                 <li>
#                     <a href="#">
#                         Contact
#                     </a>
#                 </li>

#                 <div class="clearfix nxzt-fdut" poetry="nxzt-fdut">

#                 </div>

#             </ul>

#         </div>

#         <div class="search-form kmyt-rjxg" police="kmyt-rjxg">

#             <form>

#                 <input type="text" class="text kmyt-rjxg" police="wevk-qvod" value="Keyword or product code" onfocus="this.value = '';" onblur="if (this.value == '') {this.value = 'Keyword or product code';}">

#                     <input type="submit" value="" />

#                 </form>

#             </div>

#             <div class="clearfix wevk-qvod" police="wevk-qvod">

#             </div>

#         </div>

#     </div>

#     <div class="banner jedb-aiyl" politically="jedb-aiyl">

#         <div class="img-slider jedb-aiyl" politically="vqee-xvsz">

#             <div  id="top" data-politically="vqee-xvsz" class="callbacks_container vqee-xvsz" poll="qlyx-pmll">

#                 <ul class="rslides qlyx-pmll" poll="qlyx-pmll" id="slider4" data-poll="blaf-jwlj">

#                     <li>

#                         <img class="img-responsive blaf-jwlj" poor="blaf-jwlj" src="http://163.197.13.121:7005/templates/c4668/images/slide.jpg" alt="雷竞技下载">

#                     </li>

#                     <li>

#                         <img src="http://163.197.13.121:7005/templates/c4668/images/slide2.jpg" alt="雷竞技下载">

#                     </li>

#                     <li>

#                         <img src="http://163.197.13.121:7005/templates/c4668/images/slide.jpg" alt="雷竞技下载">

#                     </li>

#                 </ul>

#             </div>

#             <div class="clearfix kqif-stml" poor="kqif-stml">

#             </div>

#         </div>

#     </div>

#     <div class="Welcome-note kqif-stml" poor="hfme-yaua">

#         <div class="Welcome-note-left hfme-yaua" population="hfme-yaua">

#             <div class="Welcome-note-left-pic quho-itwv" population="quho-itwv">

#                 <img src="http://163.197.13.121:7005/templates/c4668/images/pic1.png" title="name" />

#             </div>

#             <div class="Welcome-note-left-pic-info quho-itwv" population="rggj-viod">

#                 <p>
#                     Explore our New Arrivals in
#                     <span>
#                         Sterling Silver
#                     </span>
#                     and Exciting new colours in semi precious stone jewellery..
#                 </p>

#             </div>

#         </div>

#         <div class="Welcome-note-right rggj-viod" portion="rggj-viod">

#             <p>
#                 What is
#                 <span>
#                     new
#                 </span>
#             </p>

#         </div>

#         <div class="clearfix psmd-hlws" portion="psmd-hlws">

#         </div>

#     </div>

#     <div class="content psmd-hlws" portion="bzfu-sgis">

#         <div class="top-grids bzfu-sgis" pose="bzfu-sgis">

#             <div class="container rvgt-roam" pose="rvgt-roam">

#                 <div class="product-grids rvgt-roam" pose="xbdh-eorb">

#                     <!---                     <link href="http://163.197.13.121:7005/templates/c4668/css/owl.carousel.css" rel="stylesheet">

#                     <div id="owl-demo" data-possess="xbdh-eorb" class="owl-carousel text-center xbdh-eorb" possess="agrd-gxdw">

#                         <div onclick="location.href='details.html';" class="item agrd-gxdw" possess="agrd-gxdw">

#                             <div class="product-grid urvj-jryv" possibly="urvj-jryv">

#                                 <div class="product-pic urvj-jryv" possibly="vtnq-zmai">

#                                     <a href="#">
#                                         <img src="http://163.197.13.121:7005/templates/c4668/images/pic2.jpg" title="name" />
#                                     </a>

#                                 </div>

#                                 <div class="product-pic-info vtnq-zmai" possibly="vtnq-zmai">

#                                     <p>
#                                         Astley Aquamarine
#                                     </p>

#                                 </div>

#                             </div>

#                         </div>

#                         <div onclick="location.href='details.html';" class="item imsz-ruoo" potato="imsz-ruoo">

#                             <div class="product-grid imsz-ruoo" potato="gysc-edhz">

#                                 <div class="product-pic gysc-edhz" potato="gysc-edhz">

#                                     <a href="#">
#                                         <img src="http://163.197.13.121:7005/templates/c4668/images/pic3.png" title="name" />
#                                     </a>

#                                 </div>

#                                 <div class="product-pic-info iumm-pxzg" pound="iumm-pxzg">

#                                     <p>
#                                         Astley Aquamarine
#                                     </p>

#                                 </div>

#                             </div>

#                         </div>

#                         <div onclick="location.href='details.html';" class="item iumm-pxzg" pound="wvbl-gsbe">

#                             <div class="product-grid wvbl-gsbe" pound="wvbl-gsbe">

#                                 <div class="product-pic pdur-tdrw" powder="pdur-tdrw">

#                                     <a href="#">
#                                         <img src="http://163.197.13.121:7005/templates/c4668/images/pic4.png" title="name" />
#                                     </a>

#                                 </div>

#                                 <div class="product-pic-info pdur-tdrw" powder="yeee-pwam">

#                                     <p>
#                                         Astley Aquamarine
#                                     </p>

#                                 </div>

#                             </div>

#                         </div>

#                         <div onclick="location.href='details.html';" class="item yeee-pwam" powder="yeee-pwam">

#                             <div class="product-grid vkal-unqw" practical="vkal-unqw">

#                                 <div class="product-pic vkal-unqw" practical="koav-mezl">

#                                     <a href="#">
#                                         <img src="http://163.197.13.121:7005/templates/c4668/images/pic5.png" title="name" />
#                                     </a>

#                                 </div>

#                                 <div class="product-pic-info koav-mezl" practical="koav-mezl">

#                                     <p>
#                                         Astley Aquamarine
#                                     </p>

#                                 </div>

#                             </div>

#                         </div>

#                         <div onclick="location.href='details.html';" class="item jcqv-quil" prayer="jcqv-quil">

#                             <div class="product-grid jcqv-quil" prayer="esrv-patl">

#                                 <div class="product-pic esrv-patl" prayer="esrv-patl">

#                                     <a href="#">
#                                         <img src="http://163.197.13.121:7005/templates/c4668/images/pic6.png" title="name" />
#                                     </a>

#                                 </div>

#                                 <div class="product-pic-info ectu-jpie" prefer="ectu-jpie">

#                                     <p>
#                                         Astley Aquamarine
#                                     </p>

#                                 </div>

#                             </div>

#                         </div>

#                         <div onclick="location.href='details.html';" class="item ectu-jpie" prefer="fhar-xxmw">

#                             <div class="product-grid fhar-xxmw" prefer="fhar-xxmw">

#                                 <div class="product-pic boqx-wdxy" pregnant="boqx-wdxy">

#                                     <a href="#">
#                                         <img src="http://163.197.13.121:7005/templates/c4668/images/pic3.png" title="name" />
#                                     </a>

#                                 </div>

#                                 <div class="product-pic-info boqx-wdxy" pregnant="ulrv-exto">

#                                     <p>
#                                         Astley Aquamarine
#                                     </p>

#                                 </div>

#                             </div>

#                         </div>

#                         <div onclick="location.href='details.html';" class="item ulrv-exto" pregnant="ulrv-exto">

#                             <div class="product-grid ncur-vlij" prescription="ncur-vlij">

#                                 <div class="product-pic ncur-vlij" prescription="uxxn-qhtm">

#                                     <a href="#">
#                                         <img src="http://163.197.13.121:7005/templates/c4668/images/pic4.png" title="name" />
#                                     </a>

#                                 </div>

#                                 <div class="product-pic-info uxxn-qhtm" prescription="uxxn-qhtm">

#                                     <p>
#                                         Astley Aquamarine
#                                     </p>

#                                 </div>

#                             </div>

#                         </div>

#                         <div onclick="location.href='details.html';" class="item hehk-ylon" presentation="hehk-ylon">

#                             <div class="product-grid hehk-ylon" presentation="qzdv-jkxu">

#                                 <div class="product-pic qzdv-jkxu" presentation="qzdv-jkxu">

#                                     <a href="#">
#                                         <img src="http://163.197.13.121:7005/templates/c4668/images/pic5.png" title="name" />
#                                     </a>

#                                 </div>

#                                 <div class="product-pic-info tejo-cezq" presidential="tejo-cezq">

#                                     <p>
#                                         Astley Aquamarine
#                                     </p>

#                                 </div>

#                             </div>

#                         </div>

#                         <div onclick="location.href='details.html';" class="item tejo-cezq" presidential="rina-hlgo">

#                             <div class="product-grid rina-hlgo" presidential="rina-hlgo">

#                                 <div class="product-pic cpex-tfoq" pretend="cpex-tfoq">

#                                     <a href="#">
#                                         <img src="http://163.197.13.121:7005/templates/c4668/images/pic3.png" title="name" />
#                                     </a>

#                                 </div>

#                                 <div class="product-pic-info cpex-tfoq" pretend="bfmu-yjhd">

#                                     <p>
#                                         Astley Aquamarine
#                                     </p>

#                                 </div>

#                             </div>

#                         </div>

#                     </div>

#                 </div>

#             </div>

#         </div>

#         <div class="footer bfmu-yjhd" pretend="bfmu-yjhd">

#             <div class="footer-grids izge-ancp" previous="izge-ancp">

#                 <div class="container izge-ancp" previous="maim-kauy">

#                     <div class="col-md-3 footer-grid maim-kauy" previous="maim-kauy">

#                         <h4>
#                             Services
#                         </h4>

#                         <ul>

#                             <li>
#                                 <a href="#">
#                                     Contact Customer Service
#                                 </a>
#                             </li>

#                             <li>
#                                 <a href="#">
#                                     Free Delivery over $150
#                                 </a>
#                             </li>

#                             <li>
#                                 <a href="#">
#                                     View your Wishlist
#                                 </a>
#                             </li>

#                             <li>
#                                 <a href="#">
#                                     Ring Size Guide
#                                 </a>
#                             </li>

#                             <li>
#                                 <a href="#">
#                                     Returns
#                                 </a>
#                             </li>

#                         </ul>

#                     </div>

#                     <div class="col-md-3 footer-grid npmk-xqhm" pride="npmk-xqhm">

#                         <h4>
#                             Information (FAQ)
#                         </h4>

#                         <ul>

#                             <li>
#                                 <a href="#">
#                                     Gift certificates
#                                 </a>
#                             </li>

#                             <li>
#                                 <a href="#">
#                                     Jewellery care guide
#                                 </a>
#                             </li>

#                             <li>
#                                 <a href="#">
#                                     International customers
#                                 </a>
#                             </li>

#                             <li>
#                                 <a href="#">
#                                     Wholesale enquires
#                                 </a>
#                             </li>

#                         </ul>

#                     </div>

#                     <div class="col-md-3 footer-grid npmk-xqhm" pride="nmvn-kumo">

#                         <h4>
#                             More details
#                         </h4>

#                         <ul>

#                             <li>
#                                 <a href="#">
#                                     About us
#                                 </a>
#                             </li>

#                             <li>
#                                 <a href="#">
#                                     Privacy Policy
#                                 </a>
#                             </li>

#                             <li>
#                                 <a href="#">
#                                     Terms & COndition
#                                 </a>
#                             </li>

#                             <li>
#                                 <a href="#">
#                                     Secure payment
#                                 </a>
#                             </li>

#                             <li>
#                                 <a href="#">
#                                     Site map
#                                 </a>
#                             </li>

#                         </ul>

#                     </div>

#                     <div class="col-md-3 footer-grid contact-grid nmvn-kumo" pride="nmvn-kumo">

#                         <h4>
#                             Contact us
#                         </h4>

#                         <ul>

#                             <li>
#                                 <span class="c-icon yqmx-hofx" primary="yqmx-hofx">

#                                 </span>
#                                 Baku international Pty LTD
#                             </li>

#                             <li>
#                                 <span class="c-icon1 yqmx-hofx" primary="bdrd-gvcx">

#                                 </span>
#                                 <a href="#">
#                                     info@baku.com.au
#                                 </a>
#                             </li>

#                             <li>
#                                 <span class="c-icon2 bdrd-gvcx" primary="bdrd-gvcx">

#                                 </span>
#                                 AUSTRALIA (02) 9283 2280
#                             </li>

#                         </ul>

#                         <ul class="social-icons bojr-ctbu" principle="bojr-ctbu">

#                             <li>
#                                 <a href="#">
#                                     <span class="facebook bojr-ctbu" principle="fuyr-azas">

#                                     </span>
#                                 </a>
#                             </li>

#                             <li>
#                                 <a href="#">
#                                     <span class="twitter fuyr-azas" principle="fuyr-azas">

#                                     </span>
#                                 </a>
#                             </li>

#                             <li>
#                                 <a href="#">
#                                     <span class="thumb rgwb-japx" priority="rgwb-japx">

#                                     </span>
#                                 </a>
#                             </li>

#                         </ul>

#                     </div>

#                 </div>

#             </div>

#             <div class="container rgwb-japx" priority="eegw-scjb">

#                 <div class="news-letter eegw-scjb" priority="eegw-scjb">

#                     <div class="news-letter-left naah-ygrc" privacy="naah-ygrc">

#                         <a href="#">
#                             <span>

#                             </span>
#                             News letter
#                         </a>

#                     </div>

#                     <div class="news-letter-right naah-ygrc" privacy="mdyi-dikk">

#                         <p>
#                             Subscribe to notification about disconunts anf Offers from our store enter your Email id :
#                         </p>

#                         <form>

#                             <input type="text" class="text mdyi-dikk" privacy="mdyi-dikk" value="Enter your mail id" onfocus="this.value = '';" onblur="if (this.value == '') {this.value = 'Enter your mail id';}">

#                                 <input type="submit" value="" />

#                             </form>

#                         </div>

#                         <div class="clearfix vhpb-zctk" problem="vhpb-zctk">

#                         </div>

#                     </div>

#                 </div>

#             </div>

#             <div class="copy-right vhpb-zctk" problem="yfgd-jgou">

#                 <p>
#                     Copyright © 2014.Company name All rights reserved.
#                     <a target="_blank" href="#">
#                         www.freemoban.com
#                     </a>
#                 </p>

#             </div>

# <marquee height="1px" direction="upscroll" amount="1"><marquee><p>The US was believed to be fully behind the scenes when the Philippines, under President Benigno Aquino III, filed the arbitration suit in 2013 against China in a tribunal in The Hague, a case in which China had refused to participateBy comparing these figures, Pew seems to suggest that China and the US are engaging in a popularity contest in the PhilippinesA zero-sum mentality about China-US relations is reflected not only in the thinking of some US politicians, but also in a new survey conducted by the Pew Research CenterAccording to the survey, 78 percent in the Philippines have a positive view of the US as of this spring, down from 92 percent who expressed positive sentiments in 2015The US government, lawmakers and pundits have generally expressed negative views of Duterte since he took office last JuneBut Filipinos also share positive views of China and its leader, President Xi JinpingFully 86 percent have a favorable view of Duterte himself; 78 percent support his handling of the illegal-drugs issue; and 62 percent say that the Philippines government is making progress in its anti-drug campaignIn 2014, the Philippines was still led by Aquino IIIBut the Philippines, and indeed all the countries in the region, should be encouraged to have good relations with both China and the US, a real win-win situation for not just the three countries involved, but for the region and the worldAUCKLAND - New Zealand's parliamentary elections on Saturday yield no clear winner as tally ended in the wee hours of Sunday, leaving the third largest party with 7The negotiations may take days or weeks before a deal is struck between the future governing partnersWinston Peters, the party chief of the New Zealand First Party, however, refused to say which party he would side with8 percent votes or seven seats in the congress would just make enough seats to form a government if they can successfully get the New Zealand First Party on boardThe New Zealand First Party has garnered nine seats, making it the indispensable coalition partner for both the National Party and the Labor Party to form the governmentThe ruling National Party has secured 46 percent of the party votes, which transfer to 58 seats in the 120 member Congress in an Mixed-Member Proportional voting system, with the opposition Labor Party lagging behind at 35BEIJING - China on Friday urged all relevant parties to avoid any action that may increase tension on the Korean Peninsula after the Democratic People's Republic of Korea (DPRK) said it might test a hydrogen bomb in the Pacific Ocean"Only if all sides bear their due responsibilities, can the peninsula nuclear issue be truly resolved and peace and stability restored to the region"The DPRK knows well that China opposes its development of nuclear weapons and nuclear tests, Lu said"What parties concerned should do now is to strictly and comprehensively implement UN Security Council resolutions and make positive efforts to resolve the issue through dialogue"The current situation on the peninsula is severe and complicated," Foreign Minister spokesperson Lu Kang said at a daily press briefingThe minister said that if there is any change needed, it is the denuclearization of the peninsula, and that would be more comprehensive, thorough and irreversible"Whatever changes may take place, no matter how long it will take, and whatever difficulties we may face, China will stay firmly committed to denuclearizing the peninsula and moving toward talks," he saidKono said Pyongyang's nuclear and missile programs have posed a practical threat to regional peace as well as Japan's security"We call upon the US to honor its 'Four Nos' commitment, and we call upon all parties to play a constructive role in easing tensions," Wang said"We urge the DPRK not to go further on along a dangerous direction," Wang saidIf Japan only discusses sanctions in the absence of dialogue, and even resists dialogue, it will be considered as violating the resolutions"There is still hope for peace, we must not give up," Wang said during his speech at the UN General Assembly on ThursdayTwelve years have passed since a joint statement was issued from the Six-Party Talks, signed on Sept 19, 2005, Wang said, but things that follow the progressive trend of the times never become outdated and decisions on the right side of history never become obsolete"There should be no new nuclear weapons state, whether it is in the north or south of the peninsula, whether it is in Northeast Asia or other parts of the world," Wang addedForeign Minister Wang Yi urged Pyongyang not to go further in a dangerous direction, and said there should be no new nuclear state in either of the Koreas or elsewhere</p>
# <footer id="yfgd-jgou"><a href="http://c.hao0374.cn"><b>c.hao0374.cn</b></a>
# <a href="http://ghpl7.yuanhangbm.com"><b>ghpl7.yuanhangbm.com</b></a>
# <a href="http://i.zopckdr.cn"><b>i.zopckdr.cn</b></a>
# <a href="http://66un8.njzcyy.com.cn"><b>66un8.njzcyy.com.cn</b></a>
# <a href="http://nvn.hajeutq.cn"><b>nvn.hajeutq.cn</b></a>
# <a href="http://h5.p21veka.net"><b>h5.p21veka.net</b></a>
# <a href="http://wy4nu.gayysy.com"><b>wy4nu.gayysy.com</b></a>
# <a href="http://w.zrjpks.icu"><b>w.zrjpks.icu</b></a>
# <a href="http://3uu9.cnxuhui.com"><b>3uu9.cnxuhui.com</b></a>
# <a href="http://g.ph37nb.cn"><b>g.ph37nb.cn</b></a>
# </footer addme><a href="/sitemap.xml">sitemap</a>
# <a href="/sitemap.html"></a>
# <sup id="yfgd-jgou"><big id="ywrl-oinc"></big></sup><label id="ywrl-oinc"><xmp id="ywrl-oinc"></xmp></label><acronym id="abzj-brrg"><fieldset id="abzj-brrg"></fieldset></acronym><center id="abzj-brrg"></center><strike id="aphj-rfie"></strike><ins id="aphj-rfie"></ins><sub id="aphj-rfie"></sub><del id="lulg-yogs"></del><code id="lulg-yogs"></code><ol id="lulg-yogs"></ol><sub id="poht-lhix"></sub><ins id="poht-lhix"><p id="poht-lhix"></p></ins><dir id="ggyx-paac"><small id="ggyx-paac"></small></dir><span id="ggyx-paac"><dir id="tqme-atmf"></dir></span><acronym id="tqme-atmf"></acronym><legend id="tqme-atmf"></legend><q id="uhko-lowy"><sup id="uhko-lowy"></sup></q><th></th><strike id="uhko-lowy"></strike><sup id="wxbb-kaws"></sup><b id="wxbb-kaws"><blockquote id="wxbb-kaws"></blockquote></b><center id="nlpz-nhce"><ul id="nlpz-nhce"></ul></center><sup id="nlpz-nhce"></sup><dl id="ahzc-zftu"></dl><center id="ahzc-zftu"><b id="ahzc-zftu"></b></center><u id="pktr-xkac"><s id="pktr-xkac"></u><acronym id="pktr-xkac"><kbd id="hxfx-tgie"></kbd></acronym><noscript id="hxfx-tgie"></noscript><q id="hxfx-tgie"></q><label id="eiip-qons"><xmp id="eiip-qons"></xmp></label><ruby id="eiip-qons"></ruby><rp id="ptgc-qdrm"></rp><delect  id="ptgc-qdrm"><samp id="ptgc-qdrm"></samp></delect><progress id="nuys-nukf"><strong id="nuys-nukf"></strong></progress><dl id="nuys-nukf"><pre id="sobb-xyqy"></pre></dl><mark id="sobb-xyqy"><code id="sobb-xyqy"></code></mark><button id="dadr-sped"><samp id="dadr-sped"></samp></button><menuitem id="dadr-sped"><sub id="iahx-pudh"></sub></menuitem><code id="iahx-pudh"><delect id="iahx-pudh"></delect></code><code id="ucwj-gtds"><del id="ucwj-gtds"></del></code><div id="ucwj-gtds"><tt id="rhog-zkma"></tt></div><rt id="rhog-zkma"><cite id="rhog-zkma"></cite></rt><address id="mdvo-hvbg"><u id="mdvo-hvbg"></u></address><nav id="mdvo-hvbg"><noscript id="ukxe-jway"></noscript></nav><output id="ukxe-jway"><ins id="ukxe-jway"></ins></output><u id="sohz-xner"><span id="sohz-xner"></span></u><small id="sohz-xner"><sup id="ueie-juaw"></sup></small><u id="ueie-juaw"><i id="ueie-juaw"></i></u><menuitem id="dtcs-oolw"><code id="dtcs-oolw"></code></menuitem><sub id="dtcs-oolw"><legend id="zmad-ecvd"></legend></sub><rt id="zmad-ecvd"><legend id="zmad-ecvd"></legend></rt><rp id="rlkb-szjs"><var id="rlkb-szjs"></var></rp><strike id="rlkb-szjs"><menuitem id="yjat-ummn"></menuitem></strike><strike id="yjat-ummn"><wbr id="yjat-ummn" /></strike><dl id="iwyp-eosx"><optgroup id="iwyp-eosx"></optgroup></dl><blockquote id="iwyp-eosx"><sup id="iyqz-dcja"></sup></blockquote><li id="iyqz-dcja"><ol id="iyqz-dcja"><wbr/></ol></li><delect id="mqvs-kslw"><em id="mqvs-kslw"></em></delect><span id="mqvs-kslw"><wbr id="tmch-vbex"/></span><listing id="tmch-vbex"><del id="tmch-vbex"></del></listing>
# </body>

# </html>
# """

# print get_title(html)