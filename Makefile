
BUCKET_PREFIX := alertlogic-public-repo.
REGIONS := ap-northeast-1 ap-northeast-2 ap-south-1 ap-southeast-1 ap-southeast-2 ca-central-1 eu-central-1 eu-west-1 eu-west-2 eu-west-3 sa-east-1 us-east-1 us-east-2 us-west-1 us-west-2
PACKAGES_PREFIX := lambda_packages/
PROFILE=route105

BUCKET_NAME ?= service_not_defined
BUILD_DIR = $(shell /bin/pwd)/build
DIST_DIR = $(shell /bin/pwd)/dist
CFT_DIR := template
CFT_PREFIX := templates

s3_buckets := $(addprefix $(BUCKET_PREFIX), $(REGIONS))

TOPTARGETS := all clean package build

SUBDIRS := $(wildcard src/*/.)
ZIP_FILES := $(shell find $(DIST_DIR) -type f -name '*.zip')

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(TOPTARGETS): $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@ $(MAKECMDGOALS) $(ARGS) DIST_DIR="${DIST_DIR}"

upload: $(s3_buckets)

$(s3_buckets): | $(BUILD_DIR)
	$(eval REGION := $(word 2, $(subst ., ,${BUCKET_NAME})))
	$(info [+] Uploading artifacts to '$@' bucket)
	@$(MAKE) _upload BUCKET_NAME=$@

_upload: $(ZIP_FILES)
	$(eval REGION := $(word 2, $(subst ., ,${BUCKET_NAME})))
	@aws --profile $(PROFILE) --region $(REGION) s3 cp $(CFT_DIR)/ s3://$(BUCKET_NAME)/$(CFT_PREFIX) --recursive --exclude "*" --include "*.yaml"

$(ZIP_FILES):
	$(eval REGION := $(word 2, $(subst ., ,${BUCKET_NAME})))
	@aws --profile $(PROFILE) --region $(REGION) s3 cp $@ s3://$(BUCKET_NAME)/$(PACKAGES_PREFIX)

.PHONY: $(TOPTARGETS) $(SUBDIRS) $(s3_buckets) $(ZIP_FILES)
