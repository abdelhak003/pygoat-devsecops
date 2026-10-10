// Django CSRF token of the current session (cookie set by the page), sent in the X-CSRFToken header.
function pygoatCsrfToken() {
    var match = document.cookie.match(/(?:^|;\s*)csrftoken=([^;]+)/);
    return match ? decodeURIComponent(match[1]) : "";
}

event4 = function(){
    var code = document.getElementById('a7_input').value
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

    fetch("/2021/discussion/A7/api", requestOptions)
    .then(response => response.text())
    .then(result => {
        let data = JSON.parse(result);  // parse JSON string into object
        console.log(data);
        document.getElementById("a7_d4").style.display = 'flex';
        document.getElementById("a7_d4").innerText =  "Result: " + data.message;
        
    }
    ).catch(error => console.log('error', error));
}