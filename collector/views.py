# Copyright (c) 2013, Mike Gibson
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from collector.models import malware, tag
from django.http import HttpResponse, HttpResponseNotFound, HttpResponseRedirect, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
from django.conf import settings
from utils import jsonize, get_sample_path, store_sample, encode_sample, delete_file
from objects import File
from forms import AddMalwareForm, FindMalwareForm
import os

store_encoded = getattr(settings, 'STORE_ENCODED')

def index(request):
    if request.method == 'GET':
        latest_malware_list = malware.objects.all().order_by('-created_at')[:5]
        context = {'latest_malware_list' : latest_malware_list}
        return render(request, 'collector/index.html', context)
    else:
        return HttpResponse('METHOD not supported for URL')

def detail(request, id):
    if request.method == 'GET':
#        def details(row):
#            tags = []
#            for tag in row.tags.all():
#                tags.append(tag.tag)
#
#            entry = {
#                "id" : row.id,
#                "file_name" : row.file_name,
#                "orig_url" : row.orig_url,
#                "file_type" : row.file_type,
#                "file_size" : row.file_size,
#                "md5" : row.md5,
#                "sha1" : row.sha1,
#                "sha256" : row.sha256,
#                "sha512" : row.sha512,
#                "crc32" : row.crc32,
#                "ssdeep": row.ssdeep,
#                "created_at": row.created_at.__str__(),
#                "modified_at": row.modified_at.__str__(),
#                "tags" : tags
#            }

#            return entry

        latest_malware_list = malware.objects.all().order_by('-created_at')[:5]
        context = {'latest_malware_list' : latest_malware_list}
        return render(request, 'collector/index.html', context)

#        results = []
#        for row in latest_malware_list:
#            entry = details(row)
#            results.append(entry)

#        return HttpResponse(jsonize(results))
    else:
        return HttpResponse('METHOD not supported for URL')

def test(request):
    if request.method == 'GET':
        return HttpResponse(jsonize({"message" : "test"}))
    else:
        return HttpResponse('METHOD not supported for URL')

def list_tags(request):
    if request.method == 'GET':
        rows = tag.objects.all()

        results = []
        for row in rows:
            results.append(row.tag)

        return HttpResponse(jsonize(results))
    else:
        return HttpResponse('METHOD not supported for URL')

def get_malware(request, sha256):
    if request.method == 'GET':
        path = get_sample_path(sha256)

        if not path:
                return HttpResponseNotFound('<h1>File not found</h1>')

        return HttpResponseRedirect(path)
    else:
        return HttpResponse('METHOD not supported for URL')

@csrf_exempt
def add_malware(request):
    if request.method == 'POST':
        form = AddMalwareForm(request.POST, request.FILES)
        if form.is_valid():
            file_path=store_sample(request.FILES['file'].read())
            obj = File(file_path=file_path)
            tags = request.POST.get('tags')
            orig_url = request.POST.get('url')
            file_name = request.FILES['file'].name

        if isinstance(obj, File):
            malware_entry = malware(md5=obj.get_md5(),
                                    crc32=obj.get_crc32(),
                                    sha1=obj.get_sha1(),
                                    sha256=obj.get_sha256(),
                                    sha512=obj.get_sha512(),
                                    file_size=obj.get_size(),
                                    file_type=obj.get_type(),
                                    ssdeep=obj.get_ssdeep(),
                                    orig_url=orig_url,
                                    file_name=file_name)
        malware_entry.save()
        
        if store_encoded:
            encode_sample(file_path)
            delete_file(file_path)

        if tags:
            tags = tags.strip()
            if "," in tags:
                tags = tags.split(",")
            else:
                tags = tags.split(" ")

            for t in tags:
                t = t.strip().lower()
                if t == "":
                    continue
            
                if tag.objects.filter(tag=t).exists():
                    malware_entry.tags.add(tag.objects.get(tag=t))
                    continue

                malware_entry.tags.add(tag.objects.create(tag=t))

        return HttpResponse(jsonize({"message" : file_name + " added to repository"}))

    else:
        return HttpResponse('METHOD not supported for URL')

@csrf_exempt
def find_malware(request):
    def details(row):
        tags = []
        for tag in row.tags.all():
            tags.append(tag.tag)

        entry = {
            "id" : row.id,
            "file_name" : row.file_name,
            "orig_url" : row.orig_url,
            "file_type" : row.file_type,
            "file_size" : row.file_size,
            "md5" : row.md5,
            "sha1" : row.sha1,
            "sha256" : row.sha256,
            "sha512" : row.sha512,
            "crc32" : row.crc32,
            "ssdeep": row.ssdeep,
            "created_at": row.created_at.__str__(),
            "modified_at": row.modified_at.__str__(),
            "tags" : tags
        }

        return entry

    if request.method == 'POST':
        form = FindMalwareForm(request.POST, request.FILES)
        if form.is_valid():
            md5 = request.POST.get('md5')
            sha1 = request.POST.get('sha1')
            sha256 = request.POST.get('sha256')
            ssdeep = request.POST.get('ssdeep')
            qtag = request.POST.get('tag')
            date = request.POST.get('date')

        if md5:
            row = malware.objects.get(md5=md5)
            if row:
                return HttpResponse(jsonize(details(row)))
            else:
                return HttpResponseNotFound('<h1>Page not found</h1>') 
        elif sha1:
            row = malware.objects.get(sha1=sha1)
            if row:
                return HttpResponse(jsonize(details(row)))
            else:
                return HttpResponseNotFound('<h1>Page not found</h1>') 
        elif sha256:
            row = malware.objects.get(sha256=sha256)
            if row:
                return HttpResponse(jsonize(details(row)))
            else:
                return HttpResponseNotFound('<h1>Page not found</h1>') 
        else:
            if ssdeep:
                rows = malware.objects.filter(ssdeep=ssdeep)
            elif qtag:
                rows = tag.objects.get(tag=qtag).malware_set.all()
            elif date:
                rows = malware.objects.filter(date=date)
            else:
                return HttpResponseBadRequest("Invalid search term")

            if not rows:
                return HttpResponseNotFound('<h1>Page not found</h1>') 

            results = []
            for row in rows:
                entry = details(row)
                results.append(entry)

            return HttpResponse(jsonize(results))
    else:
        return HttpResponse('METHOD not supported for URL')
