document.getElementById("requestForm").addEventListener("submit", function(e) {
    e.preventDefault(); // Prevent the form from submitting normally

    // Get the form values
    const doctorId = document.getElementById("doctorId").value;
    const patientId = document.getElementById("patientId").value;
    const privateKey = document.getElementById("privateKey").files[0];

    // Check if a private key is selected
    if (!privateKey) {
        document.getElementById("statusMessage").innerText = "Please upload a private key file.";
        return;
    }

    // Create a FormData object to send the private key file along with other form data
    const formData = new FormData();
    formData.append("doctorId", doctorId);
    formData.append("patientId", patientId);
    formData.append("privateKey", privateKey);

    // Send the data to the backend endpoint
    fetch("/requestRecord", {
        method: "POST",
        body: formData
    })
    .then(response => response.json())  // Parse JSON response
    .then(data => {
        if (data.success) {
            document.getElementById("statusMessage").innerText = "Record request was successful.";
        } else {
            document.getElementById("statusMessage").innerText = "Failed to request record: " + data.error;
        }
    })
    .catch(error => {
        document.getElementById("statusMessage").innerText = "Error: " + error.message;
    });
});
