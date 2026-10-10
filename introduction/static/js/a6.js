// Django CSRF token of the current session (cookie set by the page), sent in the X-CSRFToken header.
function pygoatCsrfToken() {
    var match = document.cookie.match(/(?:^|;\s*)csrftoken=([^;]+)/);
    return match ? decodeURIComponent(match[1]) : "";
}

event5 = function(){
    var code = document.getElementById('a6_t1').value
    var myHeaders = new Headers();
    myHeaders.append("X-CSRFToken", pygoatCsrfToken());
    var formdata = new FormData();

    formdata.append("code", code);
    var requestOptions = {
        method: 'POST',
        headers: myHeaders,
        body: formdata,
        redirect: 'follow'
    };
    fetch("/2021/discussion/A6/api2", requestOptions)
    .then(response => response.text())
    .then(result => {
        let data = JSON.parse(result);
        // The code is reviewed statically and never stored or executed: show the review.
        alert((data.message == "success" ? "Code reviewed (not executed):\n" : "Review failed:\n")
              + (data.feedback || []).join("\n"));
    })
    .catch(error => console.log('error', error));
}

event6 = function(){
    var code = document.getElementById('a6_t1').value
    var myHeaders = new Headers();
    myHeaders.append("X-CSRFToken", pygoatCsrfToken());
    var formdata = new FormData();

    formdata.append("code", code);
    var requestOptions = {
        method: 'POST',
        headers: myHeaders,
        body: formdata,
        redirect: 'follow'
    };
    fetch("/2021/discussion/A6/api", requestOptions)
    .then(response => response.text())
    .then(result => {
        let data = JSON.parse(result);  // parse JSON string into object
        console.log(data.vulns);
        document.getElementById("a6_d5").style.display = 'flex';
        // document.getElementById("a6_d5").innerText =  data.vulns;

        for (var i = 0; i < data.vulns.length; i++) {
            var vuln = data.vulns[i];
            var vuln_div = document.createElement("div");
            vuln_div.innerText = JSON.stringify(vuln)   ;
            document.getElementById("a6_d5").appendChild(vuln_div);
        }
        
    })
    .catch(error => console.log('error', error));
}

