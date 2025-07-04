document.addEventListener("DOMContentLoaded", function () {
  const profileImage = document.getElementById("profile-image");
  const profileImageUpload = document.getElementById("profile-image-upload");
  const profileImageOverlay = document.querySelector(".profile-image-overlay");

  if (profileImageOverlay) {
    profileImageOverlay.addEventListener("click", function () {
      profileImageUpload.click();
    });
  }

  if (profileImageUpload) {
    profileImageUpload.addEventListener("change", function () {
      if (this.files && this.files[0]) {
        const formData = new FormData();
        formData.append("profile_image", this.files[0]);

        fetch("/upload_profile_image", {
          method: "POST",
          body: formData,
        })
          .then((response) => response.json())
          .then((data) => {
            if (data.success) {
              profileImage.src =
                data.profile_image_url + "?" + new Date().getTime(); // Prevent caching
              showMessage("Profile image updated successfully!", "success");
            } else {
              showMessage("Error updating profile image: " + data.message, "error");
            }
          })
          .catch((error) => {
            console.error("Error:", error);
            showMessage("An error occurred while uploading the profile image.", "error");
          });
      }
    });
  }

  // Function to display messages (success/error)
  function showMessage(message, type) {
    const messageContainer = document.getElementById("message-container");
    if (messageContainer) {
      messageContainer.textContent = message;
      messageContainer.className = "message-container show"; // Reset classes and show
      if (type === "error") {
        messageContainer.classList.add("error");
      }

      setTimeout(() => {
        messageContainer.classList.remove("show");
      }, 3000); // Message disappears after 3 seconds
    }
  }

  // Processing page functionality
  const processingStatus = document.getElementById("processingStatus");
  const detectionResults = document.getElementById("detectionResults");

  // Function to update processing status with real-time output
  window.updateProcessingStatus = function (message, isAppend = false) {
    if (processingStatus) {
      if (isAppend) {
        processingStatus.innerHTML += "<br>" + message;
      } else {
        processingStatus.textContent = message;
      }
      // Auto-scroll to bottom of status container
      processingStatus.scrollTop = processingStatus.scrollHeight;
    }
  };

  // Function to add detection result in real-time
  window.addDetectionResult = function (result) {
    if (detectionResults) {
      const resultElement = document.createElement("div");
      resultElement.className = "detection-item";
      resultElement.textContent = result;
      detectionResults.appendChild(resultElement);
    }
  };

  // Function to clear detection results
  window.clearDetectionResults = function () {
    if (detectionResults) {
      detectionResults.innerHTML = "";
    }
  };

  // Enhance the uploadAndProcess function in processing.html
  // This will be called from processing.html
  window.enhanceUploadAndProcess = function (originalFunction) {
    return async function (file) {
      // Clear previous results
      window.clearDetectionResults();

      // Show initial status
      window.updateProcessingStatus("Starting upload and processing...");

      // Call the original function
      await originalFunction(file);
    };
  };

  const sidebar = document.querySelector(".sidebar");
  const mainArea = document.querySelector(".main-area"); // Get main-area element
  const sidebarToggle = document.getElementById("sidebarToggle");

  if (sidebarToggle) {
    const sidebarToggleIcon = sidebarToggle.querySelector("i");
    // Check if the span element exists before trying to access its textContent
    const sidebarToggleText = sidebarToggle.querySelector("span");

    // Function to set sidebar state
    function setSidebarState(isHidden) {
      if (isHidden) {
        sidebar.classList.add("hidden");
        mainArea.classList.add("expanded"); // Add expanded class to main-area
        sidebarToggleIcon.classList.remove("fa-arrow-left");
        sidebarToggleIcon.classList.add("fa-arrow-right");
        if (sidebarToggleText) {
          sidebarToggleText.textContent = "Show Sidebar";
        }
      } else {
        sidebar.classList.remove("hidden");
        mainArea.classList.remove("expanded"); // Remove expanded class from main-area
        sidebarToggleIcon.classList.remove("fa-arrow-right");
        sidebarToggleIcon.classList.add("fa-arrow-left");
        if (sidebarToggleText) {
          sidebarToggleText.textContent = "Hide Sidebar";
        }
      }
    }

    // Check local storage for sidebar state on load
    const isSidebarHidden = localStorage.getItem("sidebarHidden") === "true";
    setSidebarState(isSidebarHidden);

    // Toggle sidebar on click
    sidebarToggle.addEventListener("click", function (e) {
      e.preventDefault();
      const isHidden = sidebar.classList.contains("hidden");
      setSidebarState(!isHidden);
      localStorage.setItem("sidebarHidden", !isHidden);
    });
  }
});

// Ensure the DOM is fully loaded before running scripts
document.addEventListener('DOMContentLoaded', function() {
  // All existing script.js content should be inside this block
  // ... (your existing script.js content here)
});
