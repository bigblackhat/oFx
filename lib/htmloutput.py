#coding:utf-8
def output_html(filename,vulnlist,unvulnlist,errorlist):
    newvulnlist = ["<p>"+i+"</p>" for i in vulnlist]
    newunvulnlist = ["<p>"+i+"</p>" for i in unvulnlist]
    newerrorlist = ["<p>"+i+"</p>" for i in errorlist]

    vulnstr=""
    for i in newvulnlist:
        vulnstr+=i
    unvulnstr=""
    for i in newunvulnlist:
        unvulnstr+=i
    errorstr=""
    for i in newerrorlist:
        errorstr+=i

    with open("output/%s"%(filename),"w") as f:
        f.write(html%(vulnstr,unvulnstr,errorstr))

html="""
<!DOCTYPE html>
<html lang=en>

<head>
    <meta charset=utf-8>
    <meta http-equiv=X-UA-Compatible content="IE=edge">
    <meta name=viewport content="width=device-width,initial-scale=1">
    <title>oFx Report</title>
</head>
<style>
    body {
        text-align: center
    }
    
    p.title {
        border-style: solid;
        /* 定义边框为实线 */
        border-width: 10px;
        /* 定义边框厚度 */
        border-color: #96CDCD;
        /* 定义边框颜色 */
    }
    
    p.vuln {
        border-style: solid;
        /* 定义边框为实线 */
        border-width: 10px;
        /* 定义边框厚度 */
        border-color: #4EEE94;
        /* 定义边框颜色 */
    }
    
    p.unvuln {
        border-style: solid;
        /* 定义边框为实线 */
        border-width: 10px;
        /* 定义边框厚度 */
        border-color: #8470FF;
        /* 定义边框颜色 */
    }
    
    p.unreach {
        border-style: solid;
        /* 定义边框为实线 */
        border-width: 10px;
        /* 定义边框厚度 */
        border-color: #CDCDB4;
        /* 定义边框颜色 */
    }
</style>

<body>
    <p class="title">oFx Report</p>
    <br>
    <br>
    <p class="vuln">vuln list</p>
    %s
    <br>
    <br>
    <p class="unvuln">unvuln list</p>
    %s
    <br>
    <br>
    <p class="unreach">unreach list</p>
    %s
    <br/>
    <br/>
    <br/>
    <p>powered by oFx</p>
</body>

</html>
"""