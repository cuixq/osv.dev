# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:485.0.0-alpine@sha256:d5da0344b23d03a6f2728657732c7a60300a91acaad9b8076c6fd30b1dfe1ff4

# Keep the virtualenv directly in the project directory. This isn't strictly neccesary for
# this project as it runs on kubernetes, but it keeps it consistent with other cloud run images
ENV POETRY_VIRTUALENVS_IN_PROJECT=true

RUN apk --no-cache add poetry

RUN mkdir /src
WORKDIR /src

ENV PIP_NO_BINARY ""
COPY . /src

ENV LANG en_US.UTF-8
RUN cd debian_converter && poetry install

RUN chmod +x /src/run_*
