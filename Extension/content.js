var getData;
var result;

function test(data, weight) {
    var f = 0;
    weight = [3.33346292e-01, -1.11200396e-01, -7.77821806e-01, 1.11058590e-01, 3.89430647e-01, 1.99992062e+00, 4.44366975e-01, -2.77951957e-01, -6.00531647e-05, 3.33200243e-01, 2.66644002e+00, 6.66735991e-01, 5.55496098e-01, 5.57022408e-02, 2.22225591e-01, -1.66678858e-01];
    for (var j = 0; j < data.length; j++) {
        f += data[j] * weight[j];
    }
    return f > 0 ? 1 : -1;
}

function urlHasIP() {
    var reg = /\d{1,3}[\.]{1}\d{1,3}[\.]{1}\d{1,3}[\.]{1}\d{1,3}/;
    var url = window.location.href
    if (reg.exec(url) == null) {
        console.log("NP");
        return -1;
    } else {
        console.log("P");
        return 1;
    }
}

function urlIsLong() {
    var url = window.location.href;
    if (url.length < 54) {
        console.log("NP");
        return -1;
    } else if (url.length >= 54 && url.length <= 75) {
        console.log("Maybe");
        return 0;
    } else {
        console.log("P");
        return 1;
    }
}

function urlIsShort() {
    var url = window.location.href;
    if (url.length > 20) {
        console.log("NP");
        return -1;
    } else {
        console.log("P");
        return 1;
    }
}

function urlHasAtSymbol() {
    var search = "@";
    var url = window.location.href;
    if (url.match(search) == null) {
        console.log("NP");
        return -1;
    } else {
        console.log("P");
        return 1;
    }
}

function urlHasRedirection() {
    var reg1 = /^http:/
    var reg2 = /^https:/
    var srch = "//";
    var url = window.location.href;
    if (url.search(srch) == 5 && reg1.exec(url) != null && (url.substring(7)).match(srch) == null) {
        console.log("NP");
        return -1;
    } else if (url.search(srch) == 6 && reg2.exec(url) != null && (url.substring(8)).match(srch) == null) {
        console.log("NP");
        return -1;
    } else {
        console.log("P");
        return 1;
    }
}

function urlHasHyphen() {
    var reg = /[a-zA-Z]\//;
    var srch = "-";
    var url = window.location.href;
    if (((url.substring(0, url.search(reg) + 1)).match(srch)) == null) {
        console.log("NP");
        return -1;
    } else {
        console.log("P");
        return 1;
    }
}

function urlHasMultiDomain() {
    var reg = /[a-zA-Z]\//;
    var srch = "-";
    var url = window.location.href;
    if ((url.substring(0, url.search(reg) + 1)).split('.').length < 5) {
        console.log("NP");
        return -1;
    } else {
        console.log("P");
        return 1;
    }
}

function urlHasFeviconDomain() {
    var reg = /[a-zA-Z]\//;
    var url = window.location.href;
    if (document.querySelectorAll("link[rel*='shortcut icon']").length > 0) {
        var faviconurl = document.querySelectorAll("link[rel*='shortcut icon']")[0].href;
        if ((url.substring(0, url.search(reg) + 1)) == (faviconurl.substring(0, faviconurl.search(reg) + 1))) {
            console.log("NP");
            return -1;
        } else {
            console.log("P");
            return 1;
        }
    } else {
        console.log("NP");
        return -1;
    }
}

function urlHasAnchorDifferentDomain() {
    var totalCount = document.querySelectorAll("a").length
    var identicalCount = getIdenticalDomainCount("a");
    if (((totalCount - identicalCount) / totalCount) < 0.31) {
        console.log("NP");
        return -1;
    } else if ((((totalCount - identicalCount) / totalCount) >= 0.31) && (((totalCount - identicalCount) / totalCount) <= 0.67)) {
        console.log("Maybe");
        return 0;
    } else {
        console.log("P");
        return 1;
    }
}

function urlHasIllegalHttps() {
    var srch1 = "//";
    var srch2 = "https";
    var url = window.location.href;
    if (((url.substring(url.search(srch1))).match(srch2)) == null) {
        console.log("NP");
        return -1;
    } else {
        console.log("P");
        return 1;
    }
}

function urlHasImgDifferentDomain() {
    var totalCount = document.querySelectorAll("img").length
    var identicalCount = getIdenticalDomainCount("img");
    if (((totalCount - identicalCount) / totalCount) < 0.22) {
        console.log("NP");
        return -1;
    } else if ((((totalCount - identicalCount) / totalCount) >= 0.22) && (((totalCount - identicalCount) / totalCount) <= 0.61)) {
        console.log("Maybe");
        return 0;
    } else {
        console.log("P");
        return 1;
    }
}



function urlHasScLinkDifferentDomain() {
    var totalCount = document.querySelectorAll("script").length + document.querySelectorAll("link").length
    var identicalCount = getIdenticalDomainCount("script") + getIdenticalDomainCount("link");
    if (((totalCount - identicalCount) / totalCount) < 0.17) {
        console.log("NP");
        return -1;
    } else if ((((totalCount - identicalCount) / totalCount) >= 0.17) && (((totalCount - identicalCount) / totalCount) <= 0.81)) {
        console.log("Maybe");
        return 0;
    } else {
        console.log("P");
        return 1;
    }
}

function urlHasFormActionInvalid() {
    var totalCount = document.querySelectorAll("form").length
    var identicalCount = getIdenticalDomainCount("form");
    if (document.querySelectorAll('form[action]').length <= 0) {
        console.log("NP");
        return -1;
    } else if (identicalCount != totalCount) {
        console.log("Maybe");
        return 0;
    } else if (document.querySelectorAll('form[action*=""]').length > 0) {
        console.log("P");
        return 1;
    } else {
        console.log("NP");
        return -1;
    }
}

function urlHasMail() {
    if (document.querySelectorAll('a[href^=mailto]').length <= 0) {
        console.log("NP");
        return -1;
    } else {
        console.log("P");
        return 1;
    }
}

function urlHasStatusBarTampered() {
    if ((document.querySelectorAll("a[onmouseover*='window.status']").length <= 0) || (document.querySelectorAll("a[onclick*='location.href']").length <= 0)) {
        console.log("NP");
        return -1;
    } else {
        console.log("P");
        return 1;
    }
}

function urlHasIframe() {
    if (document.querySelectorAll('iframe').length <= 0) {
        console.log("NP");
        return -1;
    } else {
        console.log("P");
        return 1;
    }
}

function getIdenticalDomainCount(tag) {
    var i;
    var identicalCount = 0;
    var reg = /[a-zA-Z]\//;
    var url = window.location.href;
    var mainDomain = url.substring(0, url.search(reg) + 1);
    var nodeList = document.querySelectorAll(tag);
    if (tag == "img" || tag == "script") {
        nodeList.forEach(function(element, index) {
            i = nodeList[index].src
            if (mainDomain == (i.substring(0, i.search(reg) + 1))) {
                identicalCount++;
            }
        });
    } else if (tag == "form") {
        nodeList.forEach(function(element, index) {
            i = nodeList[index].action
            if (mainDomain == (i.substring(0, i.search(reg) + 1))) {
                identicalCount++;
            }
        });
    } else if (tag == "a") {
        nodeList.forEach(function(element, index) {
            i = nodeList[index].href
            if ((mainDomain == (i.substring(0, i.search(reg) + 1))) && ((i.substring(0, i.search(reg) + 1)) != null) && ((i.substring(0, i.search(reg) + 1)) != "")) {
                identicalCount++;
            }
        });
    } else {
        nodeList.forEach(function(element, index) {
            i = nodeList[index].href
            if (mainDomain == (i.substring(0, i.search(reg) + 1))) {
                identicalCount++;
            }
        });
    }
    return identicalCount;
}

getData = [urlHasIP(),
    urlIsLong(),
    urlIsShort(),
    urlHasAtSymbol(),
    urlHasRedirection(),
    urlHasHyphen(),
    urlHasMultiDomain(),
    urlHasFeviconDomain(),
    urlHasIllegalHttps(),
    urlHasImgDifferentDomain(),
    urlHasAnchorDifferentDomain(),
    urlHasScLinkDifferentDomain(),
    urlHasFormActionInvalid(),
    urlHasMail(),
    urlHasStatusBarTampered(),
    urlHasIframe()
];

result = test(getData);

console.log("this is test data" + getData);

chrome.extension.sendRequest(result);