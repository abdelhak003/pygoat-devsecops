// console.log("imported a9.js");

// Django CSRF token of the current session (cookie set by the page), sent in the X-CSRFToken header.
function pygoatCsrfToken() {
    var match = document.cookie.match(/(?:^|;\s*)csrftoken=([^;]+)/);
    return match ? decodeURIComponent(match[1]) : "";
}

event1 = function(){
    document.getElementById("a9_b1").style.display = 'none';
    document.getElementById("a9_d1").style.display = 'flex';
}

event2 = function(){
    document.getElementById("a9_b2").style.display = 'none';
    document.getElementById("a9_d2").style.display = 'flex';
}

event3 = function(){
    var log_code = document.getElementById('a9_log').value
    var target_code = document.getElementById('a9_api').value

    var myHeaders = new Headers();
    // Session cookies and the CSRF token are never hard-coded: the browser sends the user's own cookies.
    myHeaders.append("X-CSRFToken", pygoatCsrfToken());

    var formdata = new FormData();
    formdata.append("log_code", log_code);
    formdata.append("api_code", target_code);

    var requestOptions = {
    method: 'POST',
    headers: myHeaders,
    body: formdata,
    redirect: 'follow'
    };

    fetch("/2021/discussion/A9/api", requestOptions)
    .then(response => response.text())
    .then(result => {
        let data = JSON.parse(result);  // parse JSON string into object
        console.log(data.logs);
        document.getElementById("a9_d3").style.display = 'flex';
        for (var i = 0; i < data.logs.length; i++) {
            var li = document.createElement("li");
            li.textContent = data.logs[i];  // text, not HTML: log lines can contain learner input
            document.getElementById("a9_d3").appendChild(li);
        }
    })
    .catch(error => console.log('error', error));
    }