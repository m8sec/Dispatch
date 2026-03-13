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

// Global variables for folder management
var folderData = [];
var allFiles = [];
var currentFolderId = null;  // null = root folder
var folderPath = [];  // Track navigation path
var currentParamKey = '';

function ListFiles() {
    refreshParamKey();
    // First load folders
    $.ajax({
        url: `/api/folders/list`,
        dataType: "json",
        type: "get",
        success: function (folders) {
            folderData = folders;
            // Then load files
            $.ajax({
                url: `/api/files/list`,
                dataType: "json",
                type: "get",
                success: function (files) {
                    allFiles = files;
                    renderFilesAndFolders(files, folders);
                    updateBreadcrumb();
                }
            });
        },
        error: function() {
            // If folders API fails, just load files
            $.ajax({
                url: `/api/files/list`,
                dataType: "json",
                type: "get",
                success: function (files) {
                    allFiles = files;
                    renderFilesAndFolders(files, []);
                    updateBreadcrumb();
                }
            });
        }
    });
}

function refreshParamKey(callback) {
    if (!document.getElementById('ParamKey')) {
        if (callback) { callback(); }
        return;
    }
    $.ajax({
        url: `/api/files/param-key`,
        dataType: "json",
        type: "get",
        success: function (response) {
            if (response && typeof response['key'] !== 'undefined') {
                currentParamKey = response['key'] || '';
                document.getElementById('ParamKey').innerHTML = currentParamKey;
            }
            if ($.fn.dataTable.isDataTable('#file_listing')) {
                var table = $('#file_listing').DataTable();
                table.rows().invalidate().draw(false);
            }
            if (callback) { callback(); }
        },
        error: function () {
            if (callback) { callback(); }
        }
    });
}

function navigateToFolder(folderId, folderName) {
    currentFolderId = folderId;

    // Update folder path for breadcrumb
    if (folderId === null) {
        folderPath = [];
    } else {
        // Add to path if not already there
        var existingIndex = folderPath.findIndex(f => f.id === folderId);
        if (existingIndex >= 0) {
            // Going back to a previous folder - trim path
            folderPath = folderPath.slice(0, existingIndex + 1);
        } else {
            // Going into a new folder
            folderPath.push({ id: folderId, name: folderName });
        }
    }

    resetFileTable();
}

function updateBreadcrumb() {
    var breadcrumb = document.getElementById('folderBreadcrumb');
    if (!breadcrumb) return;

    var html = '<nav aria-label="breadcrumb"><ol class="breadcrumb" style="margin:0;padding:8px 0;">';
    html += '<li class="breadcrumb-item"><a href="#" onclick="navigateToFolder(null, \'\'); return false;" style="color:#42B41C;"><i class="bi bi-house-door"></i> Root</a></li>';

    folderPath.forEach(function(folder, index) {
        if (index === folderPath.length - 1) {
            html += '<li class="breadcrumb-item active" aria-current="page">' + folder.name + '</li>';
        } else {
            html += '<li class="breadcrumb-item"><a href="#" onclick="navigateToFolder(' + folder.id + ', \'' + folder.name.replace(/'/g, "\\'") + '\'); return false;" style="color:#42B41C;">' + folder.name + '</a></li>';
        }
    });

    html += '</ol></nav>';
    breadcrumb.innerHTML = html;
}

function renderFilesAndFolders(files, folders) {
    // Filter folders and files by current folder
    var combinedData = [];

    // Add folders that belong to current folder
    folders.forEach(function(folder) {
        // Show folders that are in the current folder (or root if currentFolderId is null)
        if ((currentFolderId === null && !folder.parent_id) ||
            (folder.parent_id === currentFolderId)) {
            folder.isFolder = true;
            combinedData.push(folder);
        }
    });

    // Add files that belong to current folder
    files.forEach(function(file) {
        // Show files that are in the current folder (or root if currentFolderId is null)
        if ((currentFolderId === null && !file.folder_id) ||
            (file.folder_id === currentFolderId)) {
            file.isFolder = false;
            combinedData.push(file);
        }
    });

    $("#file_listing").DataTable({
        "responsive": true,
        "aaData": combinedData,
        "searching": true,
        "order": [[1, "asc"]],
        "paging": true,
        "pageLength": 50,
        "aoColumns": [
            {
                "mData": null,
                "orderable": false,
                "mRender": function (o) {
                    if (o.isFolder) {
                        return '';  // No checkbox for folders
                    } else {
                        return '<input type="checkbox" class="file-checkbox" data-file-id="' + o['id'] + '" onchange="updateBulkActions()">';
                    }
                }
            },
            {
                "mData": null,
                "mRender": function (o) {
                    if (o.isFolder) {
                        return '<a href="#" onclick="navigateToFolder(' + o.id + ', \'' + o.folder_name.replace(/'/g, "\\'") + '\'); return false;" style="font-weight:600;text-decoration:none;color:inherit;" title="Click to open folder">' +
                            '<i class="bi bi-folder-fill folder-icon" style="color:#42B41C;cursor:pointer;"></i>' +
                            '<span style="cursor:pointer;">' + o.folder_name + '</span>' +
                            '</a>';
                    } else {
                        var html = '<a href="/file/edit?id=' + o['id'] + '" title="Click to Edit">';
                        html += o['filename'];
                        html += " " + `${o['encrypt'] ? "🔒" : ""}`;
                        html += `${o['access'] == 1 ? "🌐" : ""}`;
                        html += '</a>';
                        return html;
                    }
                }
            },
            {
                "mData": null,
                "mRender": function (o) {
                    if (o.isFolder) {
                        return '-';
                    }
                    return '<span style="color:grey;">' + (o['file_size'] || '-') + '</span>';
                }
            },
            {
                "mData": null,
                "mRender": function (o) {
                    if (o.isFolder) {
                        return '-';
                    }
                    var key = '';
                    if ($('.param_key i')[0] && $('.param_key i')[0].title == 'Enabled') {
                        key = currentParamKey || document.getElementById('ParamKey').innerHTML;
                    }
                    // Use client_port for file delivery URLs (default to 443)
                    var clientPort = o['client_port'] || 443;
                    var portStr = (clientPort == 443) ? '' : ':' + clientPort;
                    var url = location.protocol + "//" + o['ip'] + portStr + "/" + o['alias'] + key;

                    var html = o['alias'];
                    html += '<span style="float:right;">';
                    html += '<a href="' + url + '" onclick="copyURI(event, this)">';
                    html += '<i class="bi bi-clipboard" title="Click to copy"></i>';
                    html += '</a>';
                    html += '</span>';
                    return html;
                }
            },
            {
                "bSortable": true,
                "mData": null,
                "mRender": function (o) {
                    if (o.isFolder) {
                        return o['created_date'] || '-';
                    }
                    return o['upload_date'];
                }
            },
            {
                "bSortable": true,
                "mData": null,
                "mRender": function (o) {
                    if (o.isFolder) {
                        return o['created_by'] || '-';
                    }
                    return o['uploaded_by'];
                }
            },
            {
                "bSortable": true,
                "mData": null,
                "mRender": function (o) {
                    var onchangeHandler = o.isFolder ?
                        'updateFolderAccess(' + o['id'] + ', this)' :
                        'updateAccess(' + o['id'] + ', this)';

                    var html = '<select class="access_perms form-control" onchange="' + onchangeHandler + '">';
                    if (o.isFolder) {
                        html += '<option value="2"' + (o['access'] == 2 ? ' selected' : '') + '>Upload Only</option>';
                        html += '<option value="3"' + (o['access'] == 3 ? ' selected' : '') + '>Operator</option>';
                        html += '<option value="4"' + (o['access'] == 4 ? ' selected' : '') + '>Administrator</option>';
                    } else {
                        html += '<option value="1"' + (o['access'] == 1 ? ' selected' : '') + '>Public</option>';
                        html += '<option value="2"' + (o['access'] == 2 ? ' selected' : '') + '>Public Once</option>';
                        html += '<option value="3"' + (o['access'] == 3 ? ' selected' : '') + '>Private</option>';
                    }
                    html += '</select>';
                    return html;
                }
            },
            {
                "mData": null,
                "mRender": function (o) {
                    var html = '<div class="actions">';

                    if (o.isFolder) {
                        // Folder actions
                        html += '<button type="button" class="btn btn-primary btn-sm" onclick="showRenameFolderModal(' + o['id'] + ', \'' + o.folder_name.replace(/'/g, "\\'") + '\')" title="Rename Folder">';
                        html += '<i class="bi bi-pencil"></i>';
                        html += '</button>';

                        html += '<button type="button" class="btn btn-danger btn-sm" onclick="deleteFolder(' + o['id'] + ')" title="Delete Folder">';
                        html += '<i class="bi bi-trash"></i>';
                        html += '</button>';
                    } else {
                        // File actions
                        var adminUrl = '/file/get/' + o['id'];

                        html += '<a href="/file/edit?id=' + o['id'] + '">';
                        html += '<button type="button" class="btn btn-primary btn-sm" title="Edit File">';
                        html += '<i class="bi bi-pencil-square"></i>';
                        html += '</button>';
                        html += '</a>';

                        html += '<a href="' + adminUrl + '?raw=true" target="_blank">';
                        html += '<button type="button" class="btn btn-secondary btn-sm">';
                        html += '<i class="bi bi-eye" title="View Raw"></i>';
                        html += '</button>';
                        html += '</a>';

                        html += '<a href="' + adminUrl + '">';
                        html += '<button type="button" class="btn btn-success btn-sm">';
                        html += '<i class="bi bi-download" title="Download"></i>';
                        html += '</button>';
                        html += '</a>';

                        html += '<button type="button" class="btn btn-warning btn-sm" onclick="showMoveFileModal(' + o['id'] + ', \'' + o['filename'].replace(/'/g, "\\'") + '\')" title="Move to Folder">';
                        html += '<i class="bi bi-folder"></i>';
                        html += '</button>';

                        html += '<a href="/file/delete?id=' + o['id'] + '">';
                        html += '<button type="button" class="btn btn-danger btn-sm">';
                        html += '<i class="bi bi-trash" title="Delete"></i>';
                        html += '</button>';
                        html += '</a>';
                    }
                    html += '</div>';
                    return html;
                }
            }
        ]
    });

    // No drag and drop - removed for simplicity
}

// Drag and drop removed - using simple move functionality instead

function resetFileTable(){
    $('#file_listing').DataTable().destroy();
    // Reload files and folders, maintaining current folder
    $.ajax({
        url: `/api/folders/list`,
        dataType: "json",
        type: "get",
        success: function (folders) {
            folderData = folders;
            $.ajax({
                url: `/api/files/list`,
                dataType: "json",
                type: "get",
                success: function (files) {
                    allFiles = files;
                    renderFilesAndFolders(files, folders);
                    updateBreadcrumb();
                }
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
            resetFileTable();
            showNotification('File access updated successfully!', true);
        },
        error: function (request, status, error){
            access_elm.style.backgroundColor = 'red';
            setTimeout(() => access_elm.style.backgroundColor = '#f0ebeb', 625);
            showNotification('Failed to update file access', false);
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
            showNotification('User role updated successfully!', true);
        },
        error: function (request, status, error){
            role_elm.style.backgroundColor = 'red';
            setTimeout(() => role_elm.style.backgroundColor = '#f0ebeb', 625);
            setTimeout(() => resetUsersTable(), 1000);
            showNotification('Failed to update user role', false);
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
    refreshParamKey(function () {
        var k = document.getElementById('ParamKey').innerHTML;
        navigator.clipboard.writeText(k).then(() => {
          elm.innerHTML = '<i style="color:#333;" class="bi bi-clipboard-check"></i>';
          setTimeout(() => elm.innerHTML = '<i class="bi bi-clipboard"></i>', 1000);
        }, () => {
          console.log('copyParamKey Failed.');
        });
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

function getMfaStatusIcon(mfaStatus) {
    // Returns MFA status icon with appropriate color
    // mfaStatus: 'enabled', 'pending', 'disabled'
    if (mfaStatus === 'enabled') {
        return '<i class="bi bi-shield-fill-check" style="color:#42B41C;" title="MFA Enabled"></i>';
    } else if (mfaStatus === 'pending') {
        return '<i class="bi bi-shield-fill-exclamation" style="color:#ffc107;" title="MFA Required - Pending Setup"></i>';
    } else {
        return '<i class="bi bi-shield" style="color:#6c757d;" title="MFA Not Enabled"></i>';
    }
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
            "order": [2, "asc" ],
            "paging": true,
            "pageLength": 50,
            "aoColumns": [
                {
                    "mData": null,
                    "orderable": false,
                    "mRender": function (o) {
                        if (o['username'] == curr_user) {
                            return '';
                        }
                        return '<input type="checkbox" class="user-checkbox" data-user-id="' + o['id'] + '" onchange="updateUserBulkActions()">';
                    }
                },
                {
                    "mData"    : null,
                    "mRender": function (o) {
                        var mfaIcon = getMfaStatusIcon(o['mfa_status'] || 'disabled');
                        return mfaIcon + '&nbsp;&nbsp;<a href="/user/edit?id=' + o['id'] + '">' + o['username'] + '</a>';
                    }
                },
                {"bSortable": true, "mData": "created" },
                {"bSortable": true, "mData": "last_login" },
                {
                    "mData"    : null,
                    "mRender": function (o) {
                        var html = '<select class="access_perms form-control" onchange="updateRole('+o['id']+', this)">';
                        if (o['username'] == curr_user){
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

                        if (o['username'] != curr_user) {
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
          updateUserBulkActions();
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

// ===== FOLDER MANAGEMENT FUNCTIONS =====

function showCreateFolderModal() {
    var modal = new bootstrap.Modal(document.getElementById('createFolderModal'));
    document.getElementById('folderName').value = '';
    document.getElementById('folderAccess').value = '3';
    modal.show();
}

function createFolder() {
    var folderName = document.getElementById('folderName').value.trim();
    var access = parseInt(document.getElementById('folderAccess').value);

    if (!folderName) {
        showNotification('Folder name is required', false);
        return;
    }

    // Create folder in current folder (or root if currentFolderId is null)
    var postData = JSON.stringify({
        folder_name: folderName,
        parent_id: currentFolderId,
        access: access
    });

    $.ajax({
        url: `/api/folder/create`,
        dataType: "json",
        contentType: "application/json; charset=utf-8",
        type: "POST",
        data: postData,
        success: function (response) {
            showNotification('Folder created successfully!', true);
            bootstrap.Modal.getInstance(document.getElementById('createFolderModal')).hide();
            resetFileTable();
        },
        error: function (request, status, error) {
            showNotification('Failed to create folder', false);
        }
    });
}

function showRenameFolderModal(folderId, currentName) {
    var modal = new bootstrap.Modal(document.getElementById('renameFolderModal'));
    document.getElementById('renameFolderId').value = folderId;
    document.getElementById('newFolderName').value = currentName;
    modal.show();
}

function renameFolder() {
    var folderId = document.getElementById('renameFolderId').value;
    var newName = document.getElementById('newFolderName').value.trim();

    if (!newName) {
        showNotification('Folder name is required', false);
        return;
    }

    var postData = JSON.stringify({
        id: parseInt(folderId),
        folder_name: newName
    });

    $.ajax({
        url: `/api/folder/rename`,
        dataType: "json",
        contentType: "application/json; charset=utf-8",
        type: "POST",
        data: postData,
        success: function (response) {
            showNotification('Folder renamed successfully!', true);
            bootstrap.Modal.getInstance(document.getElementById('renameFolderModal')).hide();
            resetFileTable();
        },
        error: function (request, status, error) {
            showNotification('Failed to rename folder', false);
        }
    });
}

function deleteFolder(folderId) {
    if (!confirm('Are you sure you want to delete this folder and all contents on disk?')) {
        return;
    }

    var postData = JSON.stringify({
        id: parseInt(folderId)
    });

    $.ajax({
        url: `/api/folder/delete`,
        dataType: "json",
        contentType: "application/json; charset=utf-8",
        type: "POST",
        data: postData,
        success: function (response) {
            showNotification('Folder deleted successfully!', true);
            resetFileTable();
        },
        error: function (request, status, error) {
            showNotification('Failed to delete folder', false);
        }
    });
}

function updateFolderAccess(folderId, accessElm) {
    var postData = JSON.stringify({
        id: folderId,
        access: parseInt(accessElm.value)
    });

    $.ajax({
        url: `/api/folder/update-access`,
        dataType: "json",
        contentType: "application/json; charset=utf-8",
        type: "POST",
        data: postData,
        success: function (response) {
            accessElm.style.backgroundColor = '#42B41C';
            setTimeout(() => accessElm.style.backgroundColor = '#f0ebeb', 625);
            showNotification('Folder access updated successfully!', true);
        },
        error: function (request, status, error) {
            accessElm.style.backgroundColor = 'red';
            setTimeout(() => accessElm.style.backgroundColor = '#f0ebeb', 625);
            showNotification('Failed to update folder access', false);
        }
    });
}

// ===== SIMPLE MOVE TO FOLDER FUNCTIONALITY =====

function showMoveFileModal(fileId, fileName) {
    // Store the file ID for later use
    window.currentMoveFileId = fileId;

    // Load folders into select dropdown
    $.ajax({
        url: `/api/folders/list`,
        dataType: "json",
        type: "get",
        success: function(folders) {
            var select = document.getElementById('singleFileFolderSelect');
            select.innerHTML = '<option value="">Root Directory</option>';
            folders.forEach(function(folder) {
                var option = document.createElement('option');
                option.value = folder.id;
                option.textContent = folder.path_label || folder.folder_name;
                select.appendChild(option);
            });

            // Set modal title
            document.getElementById('moveFileModalTitle').textContent = 'Move "' + fileName + '" to Folder';

            var modal = new bootstrap.Modal(document.getElementById('moveFileModal'));
            modal.show();
        }
    });
}

function executeSingleFileMove() {
    var folderId = document.getElementById('singleFileFolderSelect').value;
    var fileId = window.currentMoveFileId;

    var postData = JSON.stringify({
        file_id: parseInt(fileId),
        folder_id: folderId ? parseInt(folderId) : null
    });

    $.ajax({
        url: `/api/folder/move-file`,
        dataType: "json",
        contentType: "application/json; charset=utf-8",
        type: "POST",
        data: postData,
        success: function (response) {
            showNotification('File moved successfully!', true);
            bootstrap.Modal.getInstance(document.getElementById('moveFileModal')).hide();
            resetFileTable();
        },
        error: function (request, status, error) {
            showNotification('Failed to move file', false);
        }
    });
}

// ===== BULK OPERATIONS =====

function toggleSelectAll(checkbox) {
    var checkboxes = document.querySelectorAll('.file-checkbox');
    checkboxes.forEach(function(cb) {
        cb.checked = checkbox.checked;
    });
    updateBulkActions();
}

function updateBulkActions() {
    var checkedBoxes = document.querySelectorAll('.file-checkbox:checked');
    var bulkActions = document.getElementById('bulkActions');

    if (checkedBoxes.length > 0) {
        bulkActions.style.display = 'inline-block';
    } else {
        bulkActions.style.display = 'none';
    }

    // Uncheck select all if not all are selected
    var allCheckboxes = document.querySelectorAll('.file-checkbox');
    var selectAllCheckbox = document.getElementById('selectAll');
    if (selectAllCheckbox) {
        selectAllCheckbox.checked = (checkedBoxes.length === allCheckboxes.length && allCheckboxes.length > 0);
    }
}

function getSelectedFileIds() {
    var selected = [];
    document.querySelectorAll('.file-checkbox:checked').forEach(function(cb) {
        selected.push(parseInt(cb.getAttribute('data-file-id')));
    });
    return selected;
}

function bulkDelete() {
    var fileIds = getSelectedFileIds();
    if (fileIds.length === 0) {
        showNotification('No files selected', false);
        return;
    }

    if (!confirm('Are you sure you want to delete ' + fileIds.length + ' file(s)?')) {
        return;
    }

    // Delete files one by one
    var deletePromises = fileIds.map(function(fileId) {
        return $.get('/file/delete?id=' + fileId);
    });

    Promise.all(deletePromises).then(function() {
        showNotification(fileIds.length + ' file(s) deleted successfully!', true);
        resetFileTable();
    }).catch(function() {
        showNotification('Some files failed to delete', false);
        resetFileTable();
    });
}

function bulkChangeAccess() {
    var access = parseInt(document.getElementById('bulkAccessSelect').value);
    if (!access) return;

    var fileIds = getSelectedFileIds();
    if (fileIds.length === 0) {
        showNotification('No files selected', false);
        return;
    }

    var updatePromises = fileIds.map(function(fileId) {
        return $.ajax({
            url: `/api/files/update-access`,
            dataType: "json",
            contentType: "application/json; charset=utf-8",
            type: "POST",
            data: JSON.stringify({id: fileId, access: access})
        });
    });

    Promise.all(updatePromises).then(function() {
        showNotification(fileIds.length + ' file(s) access updated!', true);
        document.getElementById('bulkAccessSelect').value = '';
        resetFileTable();
    }).catch(function() {
        showNotification('Some files failed to update', false);
        document.getElementById('bulkAccessSelect').value = '';
        resetFileTable();
    });
}

function bulkMoveToFolder() {
    var fileIds = getSelectedFileIds();
    if (fileIds.length === 0) {
        showNotification('No files selected', false);
        return;
    }

    // Load folders into select dropdown
    $.ajax({
        url: `/api/folders/list`,
        dataType: "json",
        type: "get",
        success: function(folders) {
            var select = document.getElementById('targetFolderSelect');
            select.innerHTML = '<option value="">Root Directory</option>';
            folders.forEach(function(folder) {
                var option = document.createElement('option');
                option.value = folder.id;
                option.textContent = folder.path_label || folder.folder_name;
                select.appendChild(option);
            });

            var modal = new bootstrap.Modal(document.getElementById('bulkMoveModal'));
            modal.show();
        }
    });
}

function executeBulkMove() {
    var folderId = document.getElementById('targetFolderSelect').value;
    var fileIds = getSelectedFileIds();

    var movePromises = fileIds.map(function(fileId) {
        return $.ajax({
            url: `/api/folder/move-file`,
            dataType: "json",
            contentType: "application/json; charset=utf-8",
            type: "POST",
            data: JSON.stringify({file_id: fileId, folder_id: folderId || null})
        });
    });

    Promise.all(movePromises).then(function() {
        showNotification(fileIds.length + ' file(s) moved successfully!', true);
        bootstrap.Modal.getInstance(document.getElementById('bulkMoveModal')).hide();
        resetFileTable();
    }).catch(function() {
        showNotification('Some files failed to move', false);
        resetFileTable();
    });
}

function toggleSelectAllUsers(checkbox) {
    document.querySelectorAll('.user-checkbox').forEach(function(cb) {
        cb.checked = checkbox.checked;
    });
    updateUserBulkActions();
}

function updateUserBulkActions() {
    var checkedBoxes = document.querySelectorAll('.user-checkbox:checked');
    var allCheckboxes = document.querySelectorAll('.user-checkbox');
    var selectAllCheckbox = document.getElementById('selectAllUsers');
    if (selectAllCheckbox) {
        selectAllCheckbox.checked = (checkedBoxes.length === allCheckboxes.length && allCheckboxes.length > 0);
    }
}

function getSelectedUserIds() {
    var selected = [];
    document.querySelectorAll('.user-checkbox:checked').forEach(function(cb) {
        selected.push(parseInt(cb.getAttribute('data-user-id')));
    });
    return selected;
}

function bulkDeleteUsers() {
    var userIds = getSelectedUserIds();
    if (userIds.length === 0) {
        showNotification('No users selected', false);
        return;
    }

    if (!confirm('Are you sure you want to delete ' + userIds.length + ' user(s)?')) {
        return;
    }

    $.ajax({
        url: `/api/users/bulk-delete`,
        dataType: "json",
        contentType: "application/json; charset=utf-8",
        type: "POST",
        data: JSON.stringify({ids: userIds}),
        success: function (response) {
            showNotification((response.deleted || 0) + ' user(s) deleted successfully!', true);
            resetUsersTable();
        },
        error: function () {
            showNotification('Failed to delete selected users', false);
            resetUsersTable();
        }
    });
}

function bulkChangeUserRole() {
    var role = parseInt(document.getElementById('bulkRoleSelect').value);
    if (!role && role !== 0) {
        return;
    }

    var userIds = getSelectedUserIds();
    if (userIds.length === 0) {
        showNotification('No users selected', false);
        document.getElementById('bulkRoleSelect').value = '';
        return;
    }

    $.ajax({
        url: `/api/users/bulk-update-role`,
        dataType: "json",
        contentType: "application/json; charset=utf-8",
        type: "POST",
        data: JSON.stringify({ids: userIds, role: role}),
        success: function (response) {
            showNotification((response.updated || 0) + ' user role(s) updated successfully!', true);
            document.getElementById('bulkRoleSelect').value = '';
            resetUsersTable();
        },
        error: function () {
            showNotification('Failed to update selected users', false);
            document.getElementById('bulkRoleSelect').value = '';
            resetUsersTable();
        }
    });
}
