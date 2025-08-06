/*
* Dispatch File Server
* Author: m8sec
*/

function showNotification(message, isSuccess = true) {
    const notification = document.getElementById('notification');
    notification.textContent = message;
    notification.className = `alert ${isSuccess ? 'alert-success' : 'alert-danger'}`;
    notification.style.display = 'block';

    setTimeout(() => {
        notification.style.display = 'none';
    }, 3000);
}

function ListFiles() {
    $.ajax({
        url: `/api/files/list`,
        dataType: "json",
        type: "get",
        success: function (response) {
            $("#file_listing").DataTable({
            "responsive": true,
            "aaData": response,
            "searching": true,
            "order": [1, "asc" ],
            "paging": true,
            "pageLength": 50,
            "aoColumns": [
                {
                    "mData"    : null,
                    "mRender": function (o) {
                        return '<a href="/file/edit?id=' + o['id'] + '" title="Click to Edit">' + o['filename'] + '</span>';
                    }
                },
                {
                    "mData"    : null,
                    "mRender": function (o) {
                        return '<span style="color:grey;">'+o['file_size']+'</span>';
                    }
                },
                {
                    "mData"    : null,
                    "mRender": function (o) {
                        if ($('.param_key i')[0].title == 'Enabled') {
                            var key = document.getElementById('ParamKey').innerHTML;
                            var url = location.protocol + "//"+ o['ip'] + "/" + o['alias'] + key;
                        }
                        else {
                            var key = false;
                            var url = location.protocol + "//"+ o['ip'] + "/" + o['alias'];
                        }

                        var html = o['alias'];
                        html += '<span style="float:right;">';
                        html += '<a href="' + url + '" onclick="copyURI(event, this)">';
                        html += '<i class="bi bi-clipboard" title="Click to copy"></i>';
                        html += '</a>';
                        html += '</span>';
                        return html;
                    }
                },
                {"bSortable": true, "mData": "upload_date" },
                {"bSortable": true, "mData": "uploaded_by" },
                {
                    "mData"    : null,
                    "mRender": function (o) {
                        var html = '<select class="access_perms form-control" onchange="updateAccess('+o['id']+', this)">';
                        html += '<option value="1"' + (o['access'] == 1 ? ' selected': '') + '>Public</option>';
                        html += '<option value="2"' + (o['access'] == 2 ? ' selected': '') + '>Public Once</option>';
                        html += '<option value="3"' + (o['access'] == 3 ? ' selected': '') + '>Private</option>';
                        html += '</select>';
                        return html;
                    }
                },
                {
                    "mData"    : null,
                    "mRender": function (o) {
                        if ($('.param_key i')[0].title == 'Enabled') {
                            var key = document.getElementById('ParamKey').innerHTML;
                            var url = "/" + o['alias'] + key;
                        }
                        else {
                            var key = false;
                            var url = location.protocol + "//"+ o['ip'] + "/" + o['alias'];
                        }

                        var html ='<div class="actions">';
                        html += '<a href="'+ url + (key == false ? '?raw=true': '&raw=true') +'" target="_blank">';
                        html += '<button type="button" class="btn btn-success btn-sm">';
                        html += '<i class="bi bi-eye" title="View Raw"></i>';
                        html += '</button>';
                        html += '</a>';

                        html += '<a href="'+ url +'">';
                        html += '<button type="button" class="btn btn-success btn-sm">';
                        html += '<i class="bi bi-download" title="Download"></i>';
                        html += '</button>';
                        html += '</a>';

                        html += '<a href="/file/delete?id=' + o['id'] + '">';
                        html+= '<button type="button" class="btn btn-success btn-sm">';
                        html += '<i class="bi bi-trash" title="Delete"></i>';
                        html += '</button>';
                        html += '</a>';
                        return html;
                    }
                },
            ]
          });
        }
    });
}

function updateAccess(id, access_elm) {
    var post_data = JSON.stringify({
            id: id ? id : false,
            access: access_elm.value ? access_elm.value : false,
    });

    $.ajax({
        url: `/api/files/update-access`,
        dataType: "json",
        contentType:"application/json; charset=utf-8",
        type: "POST",
        data: post_data,
        success: function (response) {
            access_elm.style.backgroundColor = '#42B41C';
            setTimeout(() => access_elm.style.backgroundColor = '#f0ebeb', 625);
        },
        error: function (request, status, error){
            access_elm.style.backgroundColor = 'red';
            setTimeout(() => access_elm.style.backgroundColor = '#f0ebeb', 625);
        }
    });
}

function resetUsersTable(){
    $('#Users').DataTable().destroy();
    ListUsers();
}

function updateRole(id, role_elm) {
    var post_data = JSON.stringify({
            id: id ? id : false,
            role: role_elm.value ? role_elm.value : false,
    });

    $.ajax({
        url: `/api/users/update-role`,
        dataType: "json",
        contentType:"application/json; charset=utf-8",
        type: "POST",
        data: post_data,
        success: function (response) {
            role_elm.style.backgroundColor = '#42B41C';
            setTimeout(() => role_elm.style.backgroundColor = '#f0ebeb', 625);
        },
        error: function (request, status, error){
            role_elm.style.backgroundColor = 'red';
            setTimeout(() => role_elm.style.backgroundColor = '#f0ebeb', 625);
            setTimeout(() => resetUsersTable(), 1000);
        }
    });
}

function updateAPIKey(id) {
    var post_data = JSON.stringify({id: id ? id : false});

    $.ajax({
        url: `/api/users/gen-key`,
        dataType: "json",
        contentType:"application/json; charset=utf-8",
        type: "POST",
        data: post_data,
        success: function (response) {
            var obj = document.getElementById('api_key');
            obj.value=response['key'];
        }
    });
}

function copyAPIKey(evt, elm) {
    evt.stopPropagation();
    evt.preventDefault();
    $.ajax({
        url: `/api/user/get-key`,
        type: "POST",
        success: function (response) {
            navigator.clipboard.writeText(response['key']).then(() => {
              elm.innerHTML = '<i style="color:#333;" class="bi bi-clipboard-check"></i>';
              setTimeout(() => elm.innerHTML = '<i class="bi bi-clipboard"></i>', 1000);
            }, () => {
              console.log('copyAPIKey Failed.');
            });
        }
    })
}

function ReMapFiles() {
    $.ajax({
        url: `/api/files/reload`,
        type: "GET",
        success: function (response) {}
    });
}

function copyParamKey(evt, elm) {
    evt.stopPropagation();
    evt.preventDefault();
    var k = document.getElementById('ParamKey').innerHTML;

    navigator.clipboard.writeText(k).then(() => {
      elm.innerHTML = '<i style="color:#333;" class="bi bi-clipboard-check"></i>';
      setTimeout(() => elm.innerHTML = '<i class="bi bi-clipboard"></i>', 1000);
    }, () => {
      console.log('copyParamKey Failed.');
    });
}

function copyURI(evt, elm) {
    evt.preventDefault();
    var text = elm.href;

    navigator.clipboard.writeText(text).then(() => {
      elm.innerHTML = '<i style="color:#333;" class="bi bi-clipboard-check"></i>';
      setTimeout(() => elm.innerHTML = '<i class="bi bi-clipboard"></i>', 1000);
    }, () => {
      console.log('CopyURI Failed.');
    });
}

function ListUsers() {
    $.ajax({
        url: `/api/users/list`,
        dataType: "json",
        type: "get",
        success: function (response) {
            var curr_user = document.getElementById("curr_user").innerHTML;
            var curr_role = document.getElementById("curr_role").innerHTML;

            $("#Users").DataTable({
            "responsive": true,
            "aaData": response,
            "searching": true,
            "order": [1, "asc" ],
            "paging": true,
            "pageLength": 50,
            "aoColumns": [
                {
                    "mData"    : null,
                    "mRender": function (o) {
                        return '<a href="/user/edit?id=' + o['id'] + '">' + o['username'] + '</span>';
                    }
                },
                {"bSortable": true, "mData": "created" },
                {"bSortable": true, "mData": "last_login" },
                {
                    "mData"    : null,
                    "mRender": function (o) {
                        var html = '<select class="access_perms form-control" onchange="updateRole('+o['id']+', this)">';
                        if (o['username'] == curr_user || o['id'] == 1){
                            html += '<option value="'+o['role']+'" readonly="readonly">'+o['role_name']+'</option>';
                        }
                        else {
                            html += '<option value="0"' + (o['role'] == 0 ? ' selected': '') + '>Disabled</option>';
                            html += '<option value="1"' + (o['role'] == 1 ? ' selected': '') + '>Download Only</option>';
                            html += '<option value="2"' + (o['role'] == 2 ? ' selected': '') + '>Upload Only</option>';
                            if (curr_role == "Administrator") {
                                html += '<option value="3"' + (o['role'] == 3 ? ' selected': '') + '>Operator</option>';
                                html += '<option value="4"' + (o['role'] == 4 ? ' selected': '') + '>Administrator</option>';
                            }
                        }
                        html += '</select>';
                        return html;
                    }
                },
                {
                    "mData"    : null,
                    "mRender": function (o) {
                        var html ='<div class="actions">';
                        html += '<a href="/user/edit?id=' + o['id'] + '">';
                        html+= '<button type="button" class="btn btn-success btn-sm">';
                        html += '<i class="bi bi-person-fill-lock" title="User Settings"></i>';
                        html += '</button>';
                        html += '</a>';

                        if (o['id'] != 1 && o['username'] != curr_user) {
                            html += '<a href="/user/delete?id=' + o['id'] + '">';
                            html+= '<button type="button" class="btn btn-success btn-sm">';
                            html += '<i class="bi bi-trash" title="Delete"></i>';
                            html += '</button>'
                            html += '</a>'
                        }
                        return html;
                    }
                }
            ]
          });
        }
    });
}

function validatePassword(password) {
  document.getElementById('msg_1').innerHTML = '';
  document.getElementById('msg_1').style.color = 'red';
  if (password.length < 1 || password == null) { return }

  var msg = 'Must contain at least:<br>';
  msg += '&nbsp;&nbsp;&nbsp;&nbsp;1 Number<br>';
  msg += '&nbsp;&nbsp;&nbsp;&nbsp;1 Uppercase Letter<br>';
  msg += '&nbsp;&nbsp;&nbsp;&nbsp;1 Special Character<br>';
  msg += '&nbsp;&nbsp;&nbsp;&nbsp;10 characters total<br>';

  var uppercaseRegex = /[A-Z]/;
  var numberRegex = /[0-9]/;
  var specialCharRegex = /[!@#$%^&*]/;

  if (!uppercaseRegex.test(password)) {
    document.getElementById('msg_1').innerHTML = msg;
  }

  if (!numberRegex.test(password)) {
    document.getElementById('msg_1').innerHTML = msg;
  }

  if (!specialCharRegex.test(password)) {
    document.getElementById('msg_1').innerHTML = msg;
  }

  if (password.length < 10) {
    document.getElementById('msg_1').innerHTML = msg;
  }
}

function confirmPassword(){
  document.getElementById('msg_2').innerHTML = '';
  if (document.getElementById('confirm_password').value.length < 1 || password == null) { return; }

  if (document.getElementById('password').value != document.getElementById('confirm_password').value) {
    document.getElementById('msg_2').style.color = 'red';
    document.getElementById('msg_2').innerHTML = 'Passwords do not match.';
  }
}

function GetFileNames() {
    // Get filenames for download cradle documentation
    $.ajax({
        url: `/api/files/list`,
        dataType: "json",
        type: "get",
        success: function (data) {
            var select = document.getElementById('dwnld_files');
            $.each(data, function(x){
                var opt = document.createElement('option');
                opt.value = data[x]['alias'];
                opt.innerHTML = data[x]['filename'] + '  (' + data[x]['alias'] + ')';
                select.appendChild(opt);
            })
        }
    });
    var select = document.getElementById('dwnld_files');
    if (select.options.length < 1){
        var opt = document.createElement('option');
        opt.value = 'example.txt';
        opt.innerHTML = '--';
        select.appendChild(opt);
    }
}
